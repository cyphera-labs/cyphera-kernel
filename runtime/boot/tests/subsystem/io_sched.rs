#![no_std]
#![no_main]

use frame::{boot::parse_hvm_start_info, io::qemu_exit, io::uart, println};

use kernel::io::{IoOp, IoQueue, IoRequest, WRITE_EXPIRE_NS, WRITES_STARVED};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] io_sched: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };
    kernel::init();

    println!("[test] io_sched: running tests");
    run_tests();

    println!("IO_SCHED_OK");
    qemu_exit::exit(qemu_exit::ExitCode::Success)
}

fn run_tests() {
    let now = 1_000_000_000u64;

    {
        let mut q = IoQueue::new();
        q.submit(mk(&q, IoOp::Read, 100, now));
        q.submit(mk(&q, IoOp::Write, 200, now));
        q.submit(mk(&q, IoOp::Read, 101, now));
        q.submit(mk(&q, IoOp::Write, 201, now));
        let r = q.dispatch_next(now).expect("non-empty");
        assert!(
            r.op == IoOp::Read,
            "read-prefer expected Read, got {:?}",
            r.op
        );
        println!("[test] io_sched: 1 read-prefer OK");
    }

    {
        let mut q = IoQueue::new();
        for i in 0..(WRITES_STARVED + 2) {
            q.submit(mk(&q, IoOp::Read, 100 + i as u64, now));
        }
        q.submit(mk(&q, IoOp::Write, 999, now));
        for i in 0..WRITES_STARVED {
            let r = q.dispatch_next(now).unwrap();
            assert!(r.op == IoOp::Read, "expected Read at iter {}", i);
        }
        let w = q.dispatch_next(now).unwrap();
        assert!(
            w.op == IoOp::Write,
            "starvation cap: expected Write got {:?}",
            w.op
        );
        println!("[test] io_sched: 2 write-starvation cap OK");
    }

    {
        let mut q = IoQueue::new();
        let write_at_zero = IoRequest {
            id: q.next_id(),
            op: IoOp::Write,
            lba: 500,
            n_sectors: 1,
            deadline_ns: WRITE_EXPIRE_NS,
            enqueued_ns: 0,
        };
        q.submit(write_at_zero);
        q.submit(mk(&q, IoOp::Read, 100, now));
        let dispatch_now = WRITE_EXPIRE_NS + 1_000_000_000;
        let r = q.dispatch_next(dispatch_now).unwrap();
        assert!(
            r.op == IoOp::Write,
            "expired-write override: expected Write got {:?}",
            r.op
        );
        println!("[test] io_sched: 3 expired-write override OK");
    }

    {
        let mut q = IoQueue::new();
        let r1 = q.build_request(IoOp::Read, 1000, 1, now);
        let r2 = q.build_request(IoOp::Read, 1001, 1, now);
        let id1 = r1.id;
        let id2 = r2.id;
        q.submit(r1);
        q.submit(r2);
        let first = q.dispatch_next(now).unwrap();
        let second = q.dispatch_next(now).unwrap();
        assert!(first.id == id1 && second.id == id2, "FIFO order broken");
        println!("[test] io_sched: 4 FIFO within same deadline OK");
    }

    {
        let mut q = IoQueue::new();
        assert!(q.is_empty());
        assert!(q.dispatch_next(now).is_none());
        println!("[test] io_sched: 5 empty queue OK");
    }

    {
        let mut q = IoQueue::new();
        q.submit(mk(&q, IoOp::Read, 0, now));
        q.submit(mk(&q, IoOp::Read, 1, now));
        q.submit(mk(&q, IoOp::Write, 2, now));
        let (rc, wc) = q.counts();
        assert!(rc == 2 && wc == 1, "counts wrong: ({}, {})", rc, wc);
        println!("[test] io_sched: 6 counts OK");
    }
}

fn mk(q: &IoQueue, op: IoOp, lba: u64, now: u64) -> IoRequest {
    q.build_request(op, lba, 1, now)
}
