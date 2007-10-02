;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

(defpackage #:uuid-asd
  (:use :cl :asdf))

(in-package :uuid-asd)

; @todo fill all fields
(defsystem uuid
  :name "uuid"
  :version "0.0.1"
  :maintainer "Boian Tzonev"
  :author "Boian Tzonev"
  :licence "LLGPL"
  :description "UUID Generation"
  :long-description "Lisp implementation of rfc 4122"

  :serial t ;; the dependencies are linear.
  :components ((:file "uuid"))
  :depends-on ("ironclad"))

