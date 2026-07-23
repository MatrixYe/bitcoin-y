/// @Name: bignum_test
///
/// @Date: 2026/5/19 16:49
///
/// @Author: Matrix.Ye
///
/// @Description: null
use bitcoin_y::bignum::{BigNum, BigNumError};
use bitcoin_y::uint256::Uint256;
use rusqlite::fallible_iterator::FallibleIterator;


#[test]
fn test_is_negative() {
    let cases1 = [1, 2, 4, 8, 16, 32, 64, 128];
    let cases2 = [-1, -2, -4, -8, -16, -32, -64, -128];
    let cases3 = [0, -0];

    cases1
        .into_iter()
        .map(|i| BigNum::from_i32(i))
        .for_each(|x| {
            println!("{:?}", x);
            assert_eq!(x.is_negative(), false);
            assert_eq!(x.is_positive(), true);
        });

    cases2
        .into_iter()
        .map(|i| BigNum::from_i32(i))
        .for_each(|x| {
            assert_eq!(x.is_negative(), true);
            assert_eq!(x.is_positive(), false);
        });

    cases3
        .into_iter()
        .map(|i| BigNum::from_i32(i))
        .for_each(|x| {
            assert_eq!(x.is_negative(), false);
            assert_eq!(x.is_positive(), false);
        });
}

// 测试 Rust 原生整数构造 BigNum，并验证输出符合 Bitcoin 小端有符号字节格式。
#[test]
fn test_bn_from_primitive_integers() {
    let cases = [
        (BigNum::from_i32(0), vec![]),
        (BigNum::from_i32(1), vec![0x01]),
        (BigNum::from_i32(-1), vec![0x81]),
        (BigNum::from_i64(127), vec![0x7f]),
        (BigNum::from_i64(128), vec![0x80, 0x00]),
        (BigNum::from_i64(-128), vec![0x80, 0x80]),
        (BigNum::from_u32(256), vec![0x00, 0x01]),
        (
            BigNum::from_u64(0x8000_0000),
            vec![0x00, 0x00, 0x00, 0x80, 0x00],
        ),
    ];

    for (bn, bytes) in cases {
        assert_eq!(bn.to_bytes_le(), bytes);
    }
}

// 测试0
#[test]
fn test_bn_zero() {
    let zero = BigNum::from_bytes_le(&[]);
    assert!(zero.is_zero());
    assert_eq!(zero.to_bytes_le(), Vec::<u8>::new());
    assert_eq!(BigNum::zero(), zero);
}

//测试正数
#[test]
fn test_bn_positive_values_round_trip() {
    let cases = [
        vec![0x01],
        vec![0x7f],
        vec![0x80, 0x00],
        vec![0x00, 0x01],
        vec![0x70, 0x70],
    ];

    for bytes in cases {
        let n = BigNum::from_bytes_le(&bytes);
        assert_eq!(n.to_bytes_le(), bytes);
    }
}

// 测试负数
#[test]
fn test_bn_negative_values_round_trip() {
    let cases = [vec![0x81], vec![0xff], vec![0x80, 0x80], vec![0x00, 0x81]];

    for bytes in cases {
        let n = BigNum::from_bytes_le(&bytes);
        assert_eq!(n.to_bytes_le(), bytes);
    }
}

// 测试正0 和 负0
#[test]
fn script_num_conversion_normalizes_non_minimal_zero() {
    let negative_zero = BigNum::from_bytes_le(&[0x80]);
    let padded_zero = BigNum::from_bytes_le(&[0x00, 0x00]);

    assert!(negative_zero.is_zero());
    assert!(padded_zero.is_zero());
    assert_eq!(negative_zero.to_bytes_le(), Vec::<u8>::new());
    assert_eq!(padded_zero.to_bytes_le(), Vec::<u8>::new());
}

//测试0,所有的0
#[test]
fn test_bytes_to_bignum() {
    let cases = [vec![0x00], vec![0x80], vec![0x00, 0x00], vec![0x00, 0x80]];
    let zeros: Vec<_> = cases
        .into_iter()
        .map(|bytes| BigNum::from_bytes_le(bytes.as_slice()))
        .collect();

    for bn in zeros {
        assert!(bn.is_zero());
    }
}

#[test]
fn test_bn_operators() {
    // 加法
    let add_cases = [[99, 99, 198], [-99, -99, -198], [-99, 99, 0]];
    add_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row[0]);
        let y = BigNum::from_i32(row[1]);
        let z = BigNum::from_i32(row[2]);
        assert_eq!(x + y, z);
    });

    // 减法
    let sub_cases = [[198, 99, 99], [-198, -99, -99], [-99, 99, -198]];
    sub_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row[0]);
        let y = BigNum::from_i32(row[1]);
        let z = BigNum::from_i32(row[2]);
        assert_eq!(x - y, z);
    });

    // 乘法
    let mul_cases = [[12, 12, 144], [-12, 12, -144], [-12, -12, 144]];
    mul_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row[0]);
        let y = BigNum::from_i32(row[1]);
        let z = BigNum::from_i32(row[2]);
        assert_eq!(x * y, z);
    });

    // 除法
    let div_cases = [[99, 3, 33], [-99, 3, -33], [99, -3, -33]];
    div_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row[0]);
        let y = BigNum::from_i32(row[1]);
        let z = BigNum::from_i32(row[2]);
        assert_eq!(x / y, z);
    });

    // 取模
    let rem_cases = [[99, 10, 9], [100, 10, 0], [101, 10, 1]];
    rem_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row[0]);
        let y = BigNum::from_i32(row[1]);
        let z = BigNum::from_i32(row[2]);
        assert_eq!(x % y, z);
    });

    // 左移
    let shl_cases = [(1, 8, 256), (2, 7, 256), (-2, 7, -256)];
    shl_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row.0);
        let z = BigNum::from_i32(row.2);
        assert_eq!(x << row.1, z);
    });

    // 右移：当前实现贴近原版 CBigNum::operator>>= 的保护逻辑。
    let shr_cases = [(256, 8, 1), (1, 2, 0), (-8, 1, 0)];
    shr_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row.0);
        let z = BigNum::from_i32(row.2);
        assert_eq!(x >> row.1, z);
    });

    // 复合赋值
    let mut x = BigNum::from_i32(10);
    x += BigNum::from_i32(5);
    assert_eq!(x, BigNum::from_i32(15));
    x -= BigNum::from_i32(20);
    assert_eq!(x, BigNum::from_i32(-5));
    x *= BigNum::from_i32(-2);
    assert_eq!(x, BigNum::from_i32(10));
    x /= BigNum::from_i32(3);
    assert_eq!(x, BigNum::from_i32(3));
    x %= BigNum::from_i32(2);
    assert_eq!(x, BigNum::from_i32(1));
}

#[test]
fn test_bn_compare_operators() {
    // 相等 / 不等
    let equal_cases = [
        (0, 0, true),
        (99, 99, true),
        (-99, -99, true),
        (-99, 99, false),
    ];
    equal_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row.0);
        let y = BigNum::from_i32(row.1);
        assert_eq!(x == y, row.2);
        assert_eq!(x != y, !row.2);
    });

    // 小于 / 大于 / 小于等于 / 大于等于
    let order_cases = [(-100, -99), (-1, 0), (0, 1), (99, 100)];
    order_cases.iter().for_each(|row| {
        let x = BigNum::from_i32(row.0);
        let y = BigNum::from_i32(row.1);
        assert!(x < y);
        assert!(y > x);
        assert!(x <= y);
        assert!(y >= x);
    });

    // 等值时 <= 和 >= 都成立。
    let x = BigNum::from_i32(128);
    let y = BigNum::from_bytes_le(&[0x80, 0x00]);
    assert!(x <= y);
    assert!(x >= y);
}

#[test]
fn test_bn_to_primitive_integers() {
    assert_eq!(BigNum::from_i32(127).to_i8(), Ok(127));
    assert_eq!(
        BigNum::from_i32(128).to_i8(),
        Err(BigNumError::PrimitiveOverflow { target: "i8" })
    );
    assert_eq!(
        BigNum::from_i32(-1).to_usize(),
        Err(BigNumError::PrimitiveOverflow { target: "usize" })
    );
    assert_eq!(BigNum::from_i64(i64::MAX).to_i64(), Ok(i64::MAX));
    assert_eq!(BigNum::from_u64(u32::MAX as u64).to_u32(), Ok(u32::MAX));
    assert_eq!(
        BigNum::from_u64(u32::MAX as u64 + 1).to_u32(),
        Err(BigNumError::PrimitiveOverflow { target: "u32" })
    );
}

#[test]
fn test_bn_hex_conversion() {
    let cases = [
        ("0", BigNum::zero()),
        ("ff", BigNum::from_i32(255)),
        ("0xff", BigNum::from_i32(255)),
        ("-0xff", BigNum::from_i32(-255)),
        ("+0X10", BigNum::from_i32(16)),
    ];

    cases.iter().for_each(|row| {
        assert_eq!(BigNum::from_hex(row.0), Ok(row.1.clone()));
    });

    assert_eq!(BigNum::from_i32(255).to_hex(), "ff");
    assert_eq!(BigNum::from_i32(-255).to_hex(), "-ff");
    assert_eq!(BigNum::zero().to_hex(), "0");
    assert_eq!(BigNum::from_i32(-255).to_string(), "-255");
    assert_eq!(BigNum::from_i32(255).to_string_base(16), "ff");
    assert_eq!(
        BigNum::from_hex("not-hex"),
        Err(BigNumError::InvalidHex("not-hex".to_string()))
    );
}

#[test]
fn test_equal() {
    let a = BigNum::from_i32(0x01);
    let b = BigNum::from_i32(0x0001);
    let c = BigNum::from_i32(0x000001);
    let d = BigNum::from_i32(0x00000001);
    assert_eq!(a, b);
    assert_eq!(b, c);
    assert_eq!(c, d);
}

#[test]
fn test_x() {
    let a = BigNum::from_i32(0x1d00ffff);
    println!("{}", a.to_i64().unwrap());
    println!("{:?}", a.to_uint256().to_hex());
    println!("{:?}", a.to_uint256());
}

#[test]
fn test_target1() {
    let nbits: u32 = 0x1d00ffff;
    let nbits: u32 = 486604799;
    println!("nbits {:?}", nbits);
    let target = BigNum::set_compact(nbits);
    println!("target {:?}", target);
    println!("target.to_uint256 {:?}", target.to_uint256());
    println!("target.to_uint256().to_hex() {:?}", target.to_uint256().to_hex());
}

#[test]
fn test_target2() {
    let target = Uint256::MAX >> 32;
    println!("{:?}", target.to_hex());

    let i = target.get_compact(false);
    let num = BigNum::from_uint256(target);

    println!("{:?}", num.get_compact());
    println!("0x{:08x}", num.get_compact());
}

#[test]
fn test_target3() {
    let target1 = Uint256::MAX >> 32;
    let target2 = Uint256::from_hex("0x00000000ffff0000000000000000000000000000000000000000000000000000").unwrap();

    println!("{:?}", target1.to_hex());
    println!("{:?}", target2.to_hex());

    let bn1 = BigNum::from_uint256(target1);
    let bn2 = BigNum::from_uint256(target2);

    println!("{:?}", bn1);
    println!("{:?}", bn2);

    let nbit1 = bn1.get_compact();
    let nbit2 = bn2.get_compact();

    println!("{:?}", nbit1);
    println!("{:?}", nbit2);
}


