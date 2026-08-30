;; Exercises the shadow-frame accounting. A raise skips the epilogue of every
;; frame it unwinds, so those frames never release the slots they reserved;
;; the depth has to come back from the try_table checkpoint instead.
(module
  (tag $a (param i32))
  (tag $b)

  ;; deep recurses and then throws, so a catch above unwinds several frames.
  ;; the exnref local makes each frame reserve a slot, so an unwind that skips
  ;; the epilogues leaves them reserved.
  (func $deep (param $d i32) (local $e exnref)
    (if (i32.gt_u (local.get $d) (i32.const 0))
      (then (call $deep (i32.sub (local.get $d) (i32.const 1)))))
    (throw $b))

  ;; holds an exnref in a local across a catch, so the frame reserves slots.
  (func $catching (result i32)
    (local $x exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 1)))
      (unreachable))
    (local.set $x)
    (block $h2
      (try_table (catch $b $h2) (call $deep (i32.const 8))))
    (i32.const 1))

  (func (export "unwind_once") (result i32)
    (call $catching))

  (func (export "unwind_many") (result i32)
    (local $i i32) (local $n i32)
    (loop $l
      (local.set $n (i32.add (local.get $n) (call $catching)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 100))))
    (local.get $n))
)
