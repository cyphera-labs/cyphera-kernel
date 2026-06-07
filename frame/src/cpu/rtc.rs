use crate::io::port::Port;

const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

const REG_SECONDS: u8 = 0x00;
const REG_MINUTES: u8 = 0x02;
const REG_HOURS: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
const REG_CENTURY: u8 = 0x32;
const REG_STATUS_A: u8 = 0x0A;
const REG_STATUS_B: u8 = 0x0B;

const STATUS_A_UPDATE_IN_PROGRESS: u8 = 0x80;
const STATUS_B_24_HOUR: u8 = 0x02;
const STATUS_B_BINARY: u8 = 0x04;
const HOUR_PM_BIT: u8 = 0x80;

fn read_reg(reg: u8) -> u8 {
    // SAFETY: 0x70 is the fixed CMOS register-index port for the
    // MC146818 RTC; an 8-bit handle matches its width. Read paths run
    // only during early single-CPU boot, so no other code drives this
    // port concurrently — discharging `Port::new`'s no-concurrent-driver
    // contract (it asserts non-concurrency, not exclusive ownership: this
    // fn holds the paired 0x70/0x71 handles together).
    let index: Port<u8> = unsafe { Port::new(CMOS_INDEX) };
    // SAFETY: 0x71 is the fixed CMOS data port paired with 0x70 above,
    // 8-bit wide; the same early single-CPU-boot non-concurrency holds, so
    // no other code is driving it concurrently per `Port::new`'s contract.
    let data: Port<u8> = unsafe { Port::new(CMOS_DATA) };
    index.write(reg);
    data.read()
}

#[inline]
fn bcd_to_bin(v: u8) -> u8 {
    (v & 0x0F) + ((v >> 4) * 10)
}

#[inline]
fn update_in_progress() -> bool {
    read_reg(REG_STATUS_A) & STATUS_A_UPDATE_IN_PROGRESS != 0
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn read_cmos_unix_nanos() -> Option<u64> {
    let mut last: Option<(u8, u8, u8, u8, u8, u8, u8)> = None;
    for _ in 0..100_000 {
        let mut spins = 0u32;
        while update_in_progress() {
            super::pause();
            spins += 1;
            if spins > 1_000_000 {
                return None;
            }
        }
        let snap = (
            read_reg(REG_SECONDS),
            read_reg(REG_MINUTES),
            read_reg(REG_HOURS),
            read_reg(REG_DAY),
            read_reg(REG_MONTH),
            read_reg(REG_YEAR),
            read_reg(REG_CENTURY),
        );
        if last == Some(snap) {
            break;
        }
        last = Some(snap);
    }
    let (mut sec, mut min, hour_raw, mut day, mut month, mut year2, mut century) = last?;

    let status_b = read_reg(REG_STATUS_B);
    let is_binary = status_b & STATUS_B_BINARY != 0;
    let is_24h = status_b & STATUS_B_24_HOUR != 0;

    let pm = !is_24h && (hour_raw & HOUR_PM_BIT != 0);
    let mut hour = hour_raw & !HOUR_PM_BIT;

    if !is_binary {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hour = bcd_to_bin(hour);
        day = bcd_to_bin(day);
        month = bcd_to_bin(month);
        year2 = bcd_to_bin(year2);
        century = bcd_to_bin(century);
    }

    if !is_24h {
        hour %= 12;
        if pm {
            hour += 12;
        }
    }

    let full_year = if (19..=29).contains(&century) {
        century as i64 * 100 + year2 as i64
    } else if year2 < 70 {
        2000 + year2 as i64
    } else {
        1900 + year2 as i64
    };

    if !(1..=12).contains(&(month as i64))
        || !(1..=31).contains(&(day as i64))
        || full_year < 1970
        || sec > 60
        || min > 59
        || hour > 23
    {
        return None;
    }

    let days = days_from_civil(full_year, month as i64, day as i64);
    let secs = days * 86_400 + hour as i64 * 3_600 + min as i64 * 60 + sec as i64;
    if secs < 0 {
        return None;
    }
    Some(secs as u64 * 1_000_000_000)
}
