;;;; Author Boian Tzonev <boiantz@gmail.com>
;;;; 2007, All Rights Reserved 
;;;;
;;;; This software may be distributed and used according to the terms of the Lisp Lesser GNU Public License (LLGPL)
;;;; (http://opensource.franz.com/preamble.html).

(defpackage :uuid
  (:use :common-lisp :ironclad)
  (:shadowing-import-from :common-lisp #:null) ;ironclad shadows cl:null to declare its null-cypher, I don't use either so take it from cl
  (:export :uuid :ticks-per-count* :make-null-uuid :make-uuid-from-string :make-v1-uuid :make-v3-uuid 
	   :make-v4-uuid :make-v5-uuid :+namespace-dns+ :+namespace-url+ :+namespace-oid+ 
	   :+namespace-x500+ :print-bytes :uuid-to-byte-array :byte-array-to-uuid))

(in-package :uuid)

(defvar *clock-seq* 0 
  "Holds the clock sequence. Is is set when a version 1 uuid is 
generated for the first time and remains unchanged during a whole session.")

(defvar *node* nil 
  "Holds the IEEE 802 MAC address or a random number 
  when such is not available")

(defvar *ticks-per-count* 1024 
  "Holds the amount of ticks per count. The ticks per count determine the number 
of possible version 1 uuids created for one time interval. Common Lisp provides 
INTERNAL-TIME-UINITS-PER-SECOND which gives the ticks per count for the current system so 
*ticks-per-count* can be set to INTERNAL-TIME-UINITS-PER-SECOND")

(eval-when (:compile-toplevel :load-toplevel :execute)
  #+:sbcl
  (setf *random-state* (make-random-state t))
  
  (defclass uuid ()
    ((time-low :accessor time-low :initarg :time-low :initform 0)
     (time-mid :accessor time-mid :initarg :time-mid :initform 0)
     (time-high-and-version :accessor time-high :initarg :time-high :initform 0)
     (clock-seq-and-reserved :accessor clock-seq-var :initarg :clock-seq-var :initform 0)
     (clock-seq-low :accessor clock-seq-low :initarg :clock-seq-low :initform 0)
     (node :accessor node :initarg :node :initform 0))
    (:documentation "Represents an uuid"))

  (defun make-uuid-from-string (uuid-string)
    "Creates an uuid from the string represenation of an uuid. (example input string 6ba7b810-9dad-11d1-80b4-00c04fd430c8)"
    (make-instance 'uuid
		   :time-low (parse-integer uuid-string :start 0 :end 8 :radix 16)
		   :time-mid (parse-integer uuid-string :start 9 :end 13 :radix 16)
		   :time-high (parse-integer uuid-string :start 14 :end 18 :radix 16)
		   :clock-seq-var (parse-integer uuid-string :start 19 :end 21 :radix 16)
		   :clock-seq-low (parse-integer uuid-string :start 21 :end 23 :radix 16)
		   :node (parse-integer uuid-string :start 24 :end 36 :radix 16))))

;; Those should be constants but I couldn't find a way to define a CLOS object to be constant
(defparameter +namespace-dns+ (make-uuid-from-string "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
  "The DNS Namespace. Can be used for the generation of uuids version 3 and 5")
(defparameter +namespace-url+ (make-uuid-from-string "6ba7b811-9dad-11d1-80b4-00c04fd430c8")
  "The URL Namespace. Can be used for the generation of uuids version 3 and 5")
(defparameter +namespace-oid+ (make-uuid-from-string "6ba7b812-9dad-11d1-80b4-00c04fd430c8")
  "The OID Namespace. Can be used for the generation of uuids version 3 and 5")
(defparameter +namespace-x500+ (make-uuid-from-string "6ba7b814-9dad-11d1-80b4-00c04fd430c8")
  "The x500+ Namespace. Can be used for the generation of uuids version 3 and 5")

(defun get-node-id ()
  "Get MAC address of first ethernet device"
  (let ((node
	 #+(and :linux (or :cmu :sbcl))
	 ;; todo this can be simplified a bit
	 (let ((proc #+(and :linux :cmu)
		     (ext:run-program "/sbin/ifconfig"
				      nil
				      :pty nil 
				      :wait t 
				      :output :stream 
				      :error t
				      :if-error-exists nil)
		     #+(and :linux :sbcl)
		     (sb-ext:run-program "/sbin/ifconfig" 
					 nil
					 :output :stream
					 :error t
					 :if-error-exists nil
					 :wait nil)
		     ))
	   (loop for line = (read-line #+(and :linux :cmu)
				       (extensions:process-output proc) 
				       #+(and :linux :sbcl)
				       (sb-ext:process-output proc)
				       nil) 
		 while line 
		 when (search "HWaddr" line :test #'string-equal)
		 return (parse-integer (remove #\: (subseq line 38))
				       :radix 16)))
	 #+(and :windows :clisp)
	(let ((output (ext:run-program "ipconfig" 
				       :arguments (list "/all")
				       :input nil
				       :output :stream
				       :wait t)))
	  (loop for line = (read-line output nil) while line 
		when (search "Physical" line :test #'string-equal)
		return (parse-integer (remove #\- (subseq line 37)) :radix 16)))
	))
    (when (not node)
      (setf node (dpb #b01 (byte 8 0) (random #xffffffffffff))))
    node))

	    
(defun load-bytes (b-array &key (byte-size 8) (start 0) end)
  "Helper function to load bytes from a byte-array returning them as integer"
  (let ((ret-val 0))
    (loop for i from start to end
	  for pos from (- end start) downto 0 
	  do (setf ret-val (dpb (aref b-array i) (byte byte-size (* pos byte-size)) ret-val)))
    ret-val))


(let ((uuids-this-tick 0)
      (last-time 0))
  (defun get-timestamp ()
    "Get timestamp, compensate nanoseconds intervals"
    (tagbody 
     restart
     (let ((time-now (+ (* (get-universal-time) 10000000) 100103040000000000)))
					;10010304000 is time between 1582-10-15 and 1900-01-01 in seconds
       (cond ((not (= last-time time-now))
	      (setf uuids-this-tick 0
		    last-time time-now)
	      (return-from get-timestamp time-now))
	     (T 
	      (cond ((< uuids-this-tick *ticks-per-count*)
		     (incf uuids-this-tick)
		     (return-from get-timestamp (+ time-now uuids-this-tick)))
		    (T
		     (sleep 0.0001)
		     (go restart)))))))))
	      

(defun format-v3or5-uuid (hash ver)
  "Helper function to format a version 3 or 5 uuid. Formatting means setting the appropriate version bytes."
  (when (or (= ver 3) (= ver 5))
    (make-instance 'uuid
		   :time-low (load-bytes hash :start 0 :end 3)
		   :time-mid (load-bytes hash :start 4 :end 5)
		   :time-high (cond ((= ver 3)
				     (dpb #b0011 (byte 4 12) (load-bytes hash :start 6 :end 7)))
				    ((= ver 5)
				     (dpb #b0101 (byte 4 12) (load-bytes hash :start 6 :end 7))))
		   :clock-seq-var (dpb #b10 (byte 2 6) (aref hash 8))
		   :clock-seq-low (aref hash 9)
		   :node (load-bytes hash :start 10 :end 15))))

(defmethod print-object ((id uuid) stream)
  "Prints an uuid in the string represenation of an uuid. (example string 6ba7b810-9dad-11d1-80b4-00c04fd430c8)"
  (format stream "~8,'0X-~4,'0X-~4,'0X-~2,'0X~2,'0X-~12,'0X" 
	  (time-low id)
	  (time-mid id)
	  (time-high id)
	  (clock-seq-var id)
	  (clock-seq-low id)
	  (node id)))


(defun print-bytes (stream uuid)
  "Prints the raw bytes in hex form. (example output 6ba7b8109dad11d180b400c04fd430c8)"
  (format stream "~8,'0X~4,'0X~4,'0X~2,'0X~2,'0X~12,'0X" 
	  (time-low uuid)
	  (time-mid uuid)
	  (time-high uuid)
	  (clock-seq-var uuid)
	  (clock-seq-low uuid)
	  (node uuid)))

(defun make-null-uuid ()
  "Generates a NULL uuid (i.e 00000000-0000-0000-0000-000000000000)"
  (make-instance 'uuid))


(defun make-v1-uuid ()
  "Generates a version 1 (time-based) uuid."
  (let ((timestamp (get-timestamp)))
    (when (zerop *clock-seq*)
      (setf *clock-seq* (random 10000)))
    (unless *node*
      (setf *node* (get-node-id)))
    (make-instance 'uuid
		   :time-low (ldb (byte 32 0) timestamp)
		   :time-mid (ldb (byte 16 32) timestamp)
		   :time-high (dpb #b0001 (byte 4 12) (ldb (byte 12 48) timestamp))
		   :clock-seq-var (dpb #b10 (byte 2 6) (ldb (byte 6 8) *clock-seq*))
		   :clock-seq-low (ldb (byte 8 0) *clock-seq*) 
		   :node *node*)))


(defun make-v3-uuid (namespace name)
  "Generates a version 3 (named based MD5) uuid."
  (format-v3or5-uuid 
   (digest-uuid 3 (get-bytes (print-bytes nil namespace)) name)
   3))


(defun make-v4-uuid ()
  "Generates a version 4 (random) uuid"
  (make-instance 'uuid
		 :time-low (random #xffffffff)
		 :time-mid (random #xffff)
		 :time-high (dpb #b0100 (byte 4 12) (ldb (byte 12 0) (random #xffff)))
		 :clock-seq-var (dpb #b10 (byte 2 6) (ldb (byte 8 0) (random #xff)))
		 :clock-seq-low (random #xff)
		 :node (random #xffffffffffff)))


(defun make-v5-uuid (namespace name)
  "Generates a version 5 (name based SHA1) uuid."
  (format-v3or5-uuid 
   (digest-uuid 5 (get-bytes (print-bytes nil namespace)) name)
   5))


(defun uuid-to-byte-array (uuid)
  "Converts an uuid to byte-array"
  (let ((array (make-array 16 :element-type '(unsigned-byte 8))))
    (with-slots (time-low time-mid time-high-and-version clock-seq-and-reserved clock-seq-low node)
		uuid
		(loop for i from 3 downto 0
		      do (setf (aref array (- 3 i)) (ldb (byte 8 (* 8 i)) time-low)))
		(loop for i from 5 downto 4
		      do (setf (aref array i) (ldb (byte 8 (* 8 (- 5 i))) time-mid)))
		(loop for i from 7 downto 6
		      do (setf (aref array i) (ldb (byte 8 (* 8 (- 7 i))) time-high-and-version)))
		(setf (aref array 8) (ldb (byte 8 0) clock-seq-and-reserved))
		(setf (aref array 9) (ldb (byte 8 0) clock-seq-low))
		(loop for i from 15 downto 10
		      do (setf (aref array i) (ldb (byte 8 (* 8 (- 15 i))) node)))
    array)))

(defmacro arr-to-bytes (from to array)
  "Helper macro used in byte-array-to-uuid."
  `(loop for i from ,from to ,to
	 with res = 0
	 do (setf (ldb (byte 8 (* 8 (- ,to i))) res) (aref ,array i))
	 finally (return res)))

(defun byte-array-to-uuid (array)
  "Converts a byte-array generated with uuid-to-byte-array to an uuid."
  (assert (and (= (array-rank array) 1)
	       (= (array-total-size array) 16))
	  (array)
	  "Please provide a one-dimensional array with 16 elements of type (unsigned-byte 8)")
  (make-instance 'uuid
		 :time-low (arr-to-bytes 0 3 array)
		 :time-mid (arr-to-bytes 4 5 array)
		 :time-high (arr-to-bytes 6 7 array)
		 :clock-seq-var (aref array 8)
		 :clock-seq-low (aref array 9)
		 :node (arr-to-bytes 10 15 array)))
 
(defun digest-uuid (ver uuid name)
  "Helper function that produces a digest from a namespace and a string. Used for the 
generation of version 3 and 5 uuids."
  (let ((digester (ironclad:make-digest (cond ((= ver 3) 
					       :md5)
					      ((= ver 5)
					       :sha1 )))))
   (ironclad:update-digest digester (ironclad:ascii-string-to-byte-array uuid))
   (ironclad:update-digest digester (ironclad:ascii-string-to-byte-array name))
   (ironclad:produce-digest digester)))


(defun get-bytes (uuid-string)
  "Converts a uuid-string (as returned by print-bytes) to a string of characters 
built according code-char of each number in the uuid-string"
  (with-output-to-string (out)
			 (loop for i = 0 then (+ i 2)
			       as j = (+ i 2)
			       with max = (- (length uuid-string) 2)
			       as cur-pos = (parse-integer (subseq uuid-string i j) :radix 16)
			       do (format out "~a" (code-char cur-pos))
			       while (< i max))
			 out))