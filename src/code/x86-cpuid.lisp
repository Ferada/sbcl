;;;; CPUID handling for X86-based systems

(in-package "SB!VM")

(defun u32-to-string (&rest rest)
  (loop
    with length = (length rest)
    with result = (make-string (* 4 length))
    for i from 0 by 4
    for u32 in rest
    do (loop
         for j from 0 below 4
         do (setf (char result (+ i j)) (code-char (ldb (byte 8 (* j 8)) u32))))
    finally (return result)))

(defparameter *cpuid-vendor-ids*
  '(("AMDisbetter!" :oldamd)
    ("AuthenticAMD" :amd)
    ("GenuineIntel" :intel)
    ("CentaurHauls" :via)
    ("TransmetaCPU" :oldtransmeta)
    ("GenuineTMx86" :transmeta)
    ("CyrixInstead" :cyrix)
    ("CentaurHauls" :centaur)
    ("NexGenDriven" :nexgen)
    ("UMC UMC UMC " :umc)
    ("SiS SiS SiS " :sis)
    ("Geode by NSC" :nsc)
    ("RiseRiseRise" :rise)))

(defun cpuid-vendor-id ()
  (multiple-value-bind (eax ebx ecx edx)
      (%cpuid/4 0 0 0 0)
    (let ((decoded (u32-to-string ebx edx ecx)))
      (values eax (cadr (assoc decoded *cpuid-vendor-ids* :test #'string=)) decoded))))

(defparameter *cpuid-feature-flags*
  '((:sse3 :pclmul :dtes64 :mon
     :dspcl :vmx :smx :est
     :tm2 :ssse3 :cid NIL
     :fma :cx16 :etprd :pdcm
     NIL :pcid :dca :sse4.1
     sse4.2 :x2apic :movbe :popcnt
     :tscd :aes :xsave :osxsave
     :avx :f16c :rdrand NIL)
    (:fpu :vme :de :pse
     :tsc :msr :pae :mce
     :cx8 :apic NIL :sep
     :mtrr :pge :mca :cmov
     :pat :pse36 :psn :clfl
     NIL :dtes :acpi :mmx
     :fxsr :sse :sse2 :ss
     :htt :tm1 :ia-64 :pbe)))

(defun decode-cpuid-feature-flags (value flags)
  (let (result (i 0))
    (dolist (flag flags result)
      (when (and flag (logbitp i value))
        (push flag result))
      (incf i))))

(defun cpuid-signature ()
  (multiple-value-bind (eax ebx ecx edx)
      (%cpuid/4 1 0 0 0)
    (let (flags)
      (values
       ;; (ldb (byte 4 0) eax) ; stepping
       ;; (ldb (byte 4 4) eax) ; model
       ;; (ldb (byte 4 8) eax) ; family
       (append (decode-cpuid-feature-flags ecx (car *cpuid-feature-flags*))
               (decode-cpuid-feature-flags edx (cadr *cpuid-feature-flags*)))
       flags))))

(defun cpuid-processor-name ()
  (string-trim '(#\Space #\0)
   (concatenate
    'string
    (multiple-value-call #'u32-to-string (%cpuid/4 #x80000002 0 0 0))
    (multiple-value-call #'u32-to-string (%cpuid/4 #x80000003 0 0 0))
    (multiple-value-call #'u32-to-string (%cpuid/4 #x80000004 0 0 0)))))

(defun cpuid (what)
  (ecase what
   (:vendor-id (cpuid-vendor-id))
   (:signature (cpuid-signature))
   (:processor-name (cpuid-processor-name))))
