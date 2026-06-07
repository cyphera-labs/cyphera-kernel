#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserAccessFault;

pub fn copy_cstr_from_user_no_fault(
    user_addr: u64,
    dst: &mut [u8],
) -> Result<usize, UserAccessFault> {
    let mut total = 0usize;
    while total < dst.len() {
        let cur = user_addr.wrapping_add(total as u64);
        let to_next_page = 4096 - (cur & 0xfff) as usize;
        let chunk = to_next_page.min(dst.len() - total);
        for i in 0..chunk {
            if dst[total + i] == 0 {
                return Ok(total + i);
            }
        }
        total += chunk;
    }
    Err(UserAccessFault)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn zero_len_dst_is_err() {
        let user_addr: u64 = kani::any();
        let mut dst: [u8; 0] = [];
        let result = copy_cstr_from_user_no_fault(user_addr, &mut dst);
        assert!(matches!(result, Err(_)));
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn ok_index_points_to_null() {
        let user_addr: u64 = kani::any();
        let mut dst: [u8; 8] = kani::any();

        if let Ok(n) = copy_cstr_from_user_no_fault(user_addr, &mut dst) {
            assert!(n < dst.len());
            assert!(dst[n] == 0);
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn ok_prefix_has_no_null() {
        let user_addr: u64 = kani::any();
        let mut dst: [u8; 8] = kani::any();
        let snapshot = dst;

        if let Ok(n) = copy_cstr_from_user_no_fault(user_addr, &mut dst) {
            for i in 0..n {
                assert!(snapshot[i] != 0);
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn no_null_returns_err() {
        let user_addr: u64 = kani::any();
        let mut dst: [u8; 4] = kani::any();
        for i in 0..dst.len() {
            kani::assume(dst[i] != 0);
        }

        let result = copy_cstr_from_user_no_fault(user_addr, &mut dst);
        assert!(matches!(result, Err(_)));
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn page_chunking_no_panic() {
        let page_index: u64 = kani::any();
        let user_addr = page_index.wrapping_mul(4096);
        let byte: u8 = kani::any();
        let mut dst: [u8; 1] = [byte];

        let _ = copy_cstr_from_user_no_fault(user_addr, &mut dst);
    }
}
