use crate::sync::SpinIrq;

pub mod lapic;

pub const FIRST_IRQ_VECTOR: u8 = 32;
pub const LAST_IRQ_VECTOR: u8 = 255;

pub type IrqHandler = fn(&mut IrqContext);

pub struct IrqContext {
    pub vector: u8,
}

const NUM_IRQ_SLOTS: usize = (LAST_IRQ_VECTOR as usize) - (FIRST_IRQ_VECTOR as usize) + 1;

static HANDLERS: SpinIrq<[Option<IrqHandler>; NUM_IRQ_SLOTS]> = SpinIrq::new([None; NUM_IRQ_SLOTS]);

#[derive(Debug)]
pub enum RegisterError {
    OutOfRange,
    AlreadyRegistered,
}

pub fn init() {
    crate::println!(
        "intr: dispatch ready, vectors {}..={}",
        FIRST_IRQ_VECTOR,
        LAST_IRQ_VECTOR
    );
}

pub fn register_irq(vec: u8, handler: IrqHandler) -> Result<(), RegisterError> {
    if vec < FIRST_IRQ_VECTOR {
        return Err(RegisterError::OutOfRange);
    }
    let mut h = HANDLERS.lock();
    let slot = (vec - FIRST_IRQ_VECTOR) as usize;
    if h[slot].is_some() {
        return Err(RegisterError::AlreadyRegistered);
    }
    h[slot] = Some(handler);
    Ok(())
}

pub fn unregister_irq(vec: u8) {
    if vec < FIRST_IRQ_VECTOR {
        return;
    }
    let mut h = HANDLERS.lock();
    let slot = (vec - FIRST_IRQ_VECTOR) as usize;
    h[slot] = None;
}

pub fn dispatch(vector: u8) {
    if vector < FIRST_IRQ_VECTOR {
        crate::println!("intr: spurious low-vector dispatch {vector}");
        return;
    }
    let slot = (vector - FIRST_IRQ_VECTOR) as usize;
    let handler = HANDLERS.lock()[slot];
    match handler {
        Some(h) => {
            let mut ctx = IrqContext { vector };
            h(&mut ctx);
        }
        None => {
            crate::println!("intr: spurious irq {vector}");
        }
    }
}
