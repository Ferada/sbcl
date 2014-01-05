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
    ("RiseRiseRise" :rise)
    ("VIA VIA VIA " :via)
    ("Vortex86 SoC" :vortex)
    ("KVMKVMKVMKVM" :kvm)
    ("Microsoft Hv" :hyperv)
    ("VMwareVMware" :vmware)
    ("XenVMMXenVMM" :xen)))

(defun %cpuid (eax &optional (ebx 0) (ecx 0) (edx 0))
  (%cpuid/4 eax ebx ecx edx))

(defun cpuid-highest-parameter ()
  (values (%cpuid 0)))

(defun cpuid-highest-extended-parameter ()
  (values (%cpuid #x80000000)))

(defun cpuid-vendor-id ()
  (multiple-value-bind (eax ebx ecx edx)
      (%cpuid 0)
    (let ((decoded (u32-to-string ebx edx ecx)))
      (values (cadr (assoc decoded *cpuid-vendor-ids* :test #'string=)) decoded eax))))

(defparameter *cpuid-feature-flags*
  '((:fpu    :vme    :de     :pse
     :tsc    :msr    :pae    :mce
     :cx8    :apic   NIL     :sep
     :mtrr   :pge    :mca    :cmov
     :pat    :pse36  :psn    :clfl
     NIL     :dtes   :acpi   :mmx
     :fxsr   :sse    :sse2   :ss
     :htt    :tm1    :ia-64  :pbe)
    (:sse3   :pclmul :dtes64 :mon
     :dspcl  :vmx    :smx    :est
     :tm2    :ssse3  :cid    NIL
     :fma    :cx16   :etprd  :pdcm
     NIL     :pcid   :dca    :sse4.1
     :sse4.2 :x2apic :movbe  :popcnt
     :tscd   :aes    :xsave  :osxsave
     :avx    :f16c   :rdrand NIL)))

(defun decode-cpuid-feature-flags (value flags)
  (let (result (i 0))
    (dolist (flag flags result)
      (when (and flag (logbitp i value))
        (push flag result))
      (incf i))))

(defun decode-cpuid-processor-info (vendor eax)
  (let ((stepping (ldb (byte 4 0) eax))
        (model (ldb (byte 4 4) eax))
        (family (ldb (byte 4 8) eax))
        (processor-type (ldb (byte 2 12) eax))
        (extended-model (ldb (byte 4 16) eax))
        (extended-family (ldb (byte 4 20) eax)))
    (flet ((intel ()
             (list stepping
                   (+ model (ash extended-model 4))
                   (+ family extended-family)
                   processor-type)))
      (case vendor
        ((:oldamd :amd)
         (if (eql family 15)
             (intel)
             (list stepping model family processor-type)))
        (T
         (intel))))))

(defun cpuid-signature (&optional (vendor-id (cpuid-vendor-id)))
  (when (< (cpuid-highest-parameter) 1)
    (warn "Processor info feature unsupported by CPU.")
    (return-from cpuid-signature))
  (multiple-value-bind (eax ebx ecx edx)
      (%cpuid 1)
    (values
     (append (decode-cpuid-feature-flags edx (car *cpuid-feature-flags*))
             (decode-cpuid-feature-flags ecx (cadr *cpuid-feature-flags*)))
     (decode-cpuid-processor-info vendor-id eax))))

(defun cpuid-processor-name ()
  (when (< (cpuid-highest-extended-parameter) #x80000004)
    (warn "Processor name feature unsupported by CPU.")
    (return-from cpuid-processor-name))
  (string-trim
   '(#\Space #\Nul)
   (multiple-value-call #'u32-to-string
     (%cpuid #x80000002)
     (%cpuid #x80000003)
     (%cpuid #x80000004))))

(defun cpuid (what)
  (unless (cpuid-available-p)
    (warn "CPUID instruction unsupported by CPU.")
    (return-from cpuid))
  (ecase what
   (:vendor-id (cpuid-vendor-id))
   (:signature (cpuid-signature))
   (:processor-name (cpuid-processor-name))))
