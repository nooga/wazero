;; Two exceptions are live at once: A is caught by reference and parked in a
;; local (or a global), B is thrown and caught while A is still held, then A
;; is rethrown and its param read back. Nothing in Go references A between the
;; catch and the rethrow, so an engine that roots only the most recent
;; exception lets A be collected. See wazero/wazero#2522.
(module
  ;; churn asks the host to collect and then overwrite freed memory.
  (import "env" "churn" (func $churn))

  (tag $a (param i32))
  (tag $b)
  (global $ge (mut exnref) (ref.null exn))

  ;; throw_b overwrites the engine's most-recent-exception slot with B.
  (func $throw_b
    (block $h
      (try_table (catch $b $h) (throw $b))))

  ;; rethrow raises x again and reads the i32 it carries.
  (func $rethrow (param $x exnref) (result i32)
    (block $h (result i32)
      (try_table (catch $a $h) (throw_ref (local.get $x)))
      (unreachable)))

  (func (export "exnref_local") (result i32)
    (local $x exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 13)))
      (unreachable))
    (local.set $x)
    (call $throw_b)
    (call $churn)
    (call $rethrow (local.get $x)))

  ;; stash catches A into the global and returns, so the frame that caught it
  ;; is gone: only the global can be keeping A alive.
  (func $stash
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 15)))
      (unreachable))
    (global.set $ge))

  ;; deep throws from a nested frame, so the catch below unwinds frames whose
  ;; epilogues never run and whose shadow slots are therefore never released.
  (func $deep (param $d i32)
    (if (i32.gt_u (local.get $d) (i32.const 0))
      (then (call $deep (i32.sub (local.get $d) (i32.const 1)))))
    (throw $b))

  ;; A is caught and parked in a local, then a second exception is raised from
  ;; several frames down and caught here. The unwind must not move the base
  ;; this frame's slots are addressed from, or $x stops being rooted.
  (func (export "exnref_unwind") (result i32)
    (local $x exnref)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 16)))
      (unreachable))
    (local.set $x)
    (block $h2
      (try_table (catch $b $h2) (call $deep (i32.const 8))))
    (call $scrub)
    (call $churn)
    (call $rethrow (local.get $x)))

  ;; scrub catches many exceptions into locals, so any slot a returned frame
  ;; left behind is overwritten. Without it a stale slot can still be holding
  ;; A, and the test would pass without the global rooting anything.
  (func $scrub
    (local $i i32) (local $y exnref) (local $z exnref)
    (loop $l
      (block $h (result exnref)
        (try_table (catch_all_ref $h) (throw $b))
        (unreachable))
      (local.set $y)
      (local.set $z (local.get $y))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 64)))))

  (func (export "exnref_global_cross_call") (result i32)
    (call $stash)
    (call $scrub)
    (call $churn)
    (call $rethrow (global.get $ge)))

  (func (export "exnref_global") (result i32)
    (block $h (result exnref)
      (try_table (catch_all_ref $h) (throw $a (i32.const 14)))
      (unreachable))
    (global.set $ge)
    (call $throw_b)
    (call $churn)
    (call $rethrow (global.get $ge)))
)
