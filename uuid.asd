;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-

(defpackage #:uuid-asd
  (:use :cl :asdf))

(in-package :uuid-asd)

(defsystem uuid
  :name "uuid"
  :version "2012.12.26"
  :maintainer "Boian Tzonev"
  :author "Boian Tzonev"
  :licence "LLGPL"
  :description "UUID Generation"
  :long-description "Lisp implementation of rfc 4122"

  :serial t ;; the dependencies are linear.
  :components ((:file "uuid"))
  :depends-on ("ironclad" "trivial-utf-8"))

