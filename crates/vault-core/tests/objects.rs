//! Encrypted file objects: round-trips at every boundary size, random access, and the complete tamper
//! matrix from docs/FILE_FORMAT.md (corruption, truncation, extension, reorder, duplicate, wrong key,
//! wrong object, wrong vault).
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::needless_range_loop)] // the exhaustive byte loops index a fresh clone on purpose
mod common;
use common::*;
use proptest::prelude::*;
use std::{
    collections::HashSet,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};
use usna_vault_core::{
    FileKey, ObjectId, ObjectReader, ObjectWriter, UnlockedVault, DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, OBJECT_HEADER_LEN,
};

const CS: u32 = 4096;
const STRIDE: usize = CS as usize + 16;

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i >> 8)) as u8)
        .collect()
}

fn seal(v: &UnlockedVault, id: &ObjectId, key: &FileKey, data: &[u8], cs: u32) -> Vec<u8> {
    let mut w = ObjectWriter::new(Vec::new(), v.vault_id(), id, key, cs).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

fn open<'a>(
    v: &UnlockedVault,
    id: &ObjectId,
    key: &FileKey,
    bytes: &'a [u8],
) -> std::io::Result<ObjectReader<Cursor<&'a [u8]>>> {
    ObjectReader::open(Cursor::new(bytes), v.vault_id(), id, key)
}

fn read_all(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

/// True if opening or fully verifying the (possibly modified) object fails.
fn rejected(v: &UnlockedVault, id: &ObjectId, key: &FileKey, bytes: &[u8]) -> bool {
    match open(v, id, key, bytes) {
        Err(_) => true,
        Ok(mut r) => r.verify_all().is_err(),
    }
}

fn setup() -> (UnlockedVault, ObjectId, FileKey) {
    let (v, _h) = new_vault();
    let id = oid();
    let (key, _wrapped) = v.new_file_key(&id).unwrap();
    (v, id, key)
}

#[test]
fn roundtrip_at_every_boundary_size() {
    let (v, id, key) = setup();
    let cs = CS as usize;
    for n in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 2 * cs + 1, 3 * cs + 17] {
        let data = pattern(n);
        let obj = seal(&v, &id, &key, &data, CS);
        let chunks = n.div_ceil(cs).max(1);
        assert_eq!(
            obj.len(),
            OBJECT_HEADER_LEN + 16 * chunks + n,
            "stored size for n={n}"
        );
        let mut r = open(&v, &id, &key, &obj).unwrap();
        assert_eq!(r.len(), n as u64);
        assert_eq!(read_all(&mut r).unwrap(), data, "n={n}");
        assert_eq!(r.verify_all().unwrap(), n as u64);
    }
}

#[test]
fn exact_multiple_ends_with_a_full_final_chunk_and_no_empty_trailer() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(2 * CS as usize), CS);
    assert_eq!(obj.len(), OBJECT_HEADER_LEN + 2 * STRIDE);
}

#[test]
fn empty_file_is_one_final_empty_chunk() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &[], CS);
    assert_eq!(obj.len(), OBJECT_HEADER_LEN + 16);
    let mut r = open(&v, &id, &key, &obj).unwrap();
    assert!(r.is_empty());
    assert!(read_all(&mut r).unwrap().is_empty());
}

#[test]
fn writes_in_odd_pieces_produce_a_valid_object() {
    let (v, id, key) = setup();
    let data = pattern(3 * CS as usize + 123);
    let mut w = ObjectWriter::new(Vec::new(), v.vault_id(), &id, &key, CS).unwrap();
    for piece in data.chunks(777) {
        w.write_all(piece).unwrap();
    }
    let obj = w.finish().unwrap();
    assert_eq!(
        read_all(&mut open(&v, &id, &key, &obj).unwrap()).unwrap(),
        data
    );
}

#[test]
fn reads_in_tiny_pieces_match() {
    let (v, id, key) = setup();
    let data = pattern(2 * CS as usize + 50);
    let obj = seal(&v, &id, &key, &data, CS);
    let mut r = open(&v, &id, &key, &obj).unwrap();
    let mut out = Vec::new();
    let mut b = [0u8; 7];
    loop {
        let n = r.read(&mut b).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n]);
    }
    assert_eq!(out, data);
}

#[test]
fn random_access_reads_match_the_original() {
    let (v, id, key) = setup();
    let data = pattern(5 * CS as usize + 999);
    let obj = seal(&v, &id, &key, &data, CS);
    let mut r = open(&v, &id, &key, &obj).unwrap();
    let cs = CS as usize;
    for (start, len) in [
        (0, 10),
        (cs - 5, 20),
        (cs, cs),
        (2 * cs + 7, 3 * cs),
        (data.len() - 3, 3),
        (data.len(), 0),
    ] {
        r.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut got = vec![0u8; len];
        r.read_exact(&mut got).unwrap();
        assert_eq!(got, data[start..start + len], "start={start} len={len}");
    }
    assert_eq!(r.seek(SeekFrom::End(-10)).unwrap(), data.len() as u64 - 10);
    assert_eq!(read_all(&mut r).unwrap(), data[data.len() - 10..]);
    assert_eq!(
        r.seek(SeekFrom::Current(-5)).unwrap(),
        data.len() as u64 - 5
    );
    assert!(r.seek(SeekFrom::Current(-(data.len() as i64) * 2)).is_err());
    r.seek(SeekFrom::Start(data.len() as u64 + 100)).unwrap();
    assert_eq!(
        r.read(&mut [0u8; 8]).unwrap(),
        0,
        "reading past the end returns 0"
    );
}

#[test]
fn default_chunk_size_roundtrips_a_multi_chunk_file() {
    let (v, id, key) = setup();
    let data = pattern(2 * DEFAULT_CHUNK_SIZE as usize + 12_345);
    let obj = seal(&v, &id, &key, &data, DEFAULT_CHUNK_SIZE);
    assert_eq!(
        read_all(&mut open(&v, &id, &key, &obj).unwrap()).unwrap(),
        data
    );
}

#[test]
fn plaintext_does_not_appear_in_the_object() {
    let (v, id, key) = setup();
    let marker = b"OBJECT-PLAINTEXT-MARKER-0123456789-ABCDEF";
    let mut data = pattern(CS as usize);
    data[100..100 + marker.len()].copy_from_slice(marker);
    let obj = seal(&v, &id, &key, &data, CS);
    assert!(!obj.windows(marker.len()).any(|w| w == marker));
}

// ---------------------------------------------------------------- tamper matrix --------------

#[test]
fn every_single_byte_modification_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(2 * CS as usize + 100), CS);
    assert!(
        !rejected(&v, &id, &key, &obj),
        "control: untouched object must verify"
    );
    for i in 0..obj.len() {
        let mut m = obj.clone();
        m[i] ^= 0x01;
        assert!(
            rejected(&v, &id, &key, &m),
            "modification of byte {i} was accepted"
        );
    }
}

#[test]
fn every_truncation_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(3 * CS as usize), CS);
    for len in 0..obj.len() {
        assert!(
            rejected(&v, &id, &key, &obj[..len]),
            "truncation to {len} bytes was accepted"
        );
    }
}

#[test]
fn truncating_at_a_chunk_boundary_fails_because_of_the_final_flag() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(3 * CS as usize), CS);
    // Remove the last chunk exactly: geometry is valid, only the final flag can catch it.
    let cut = &obj[..OBJECT_HEADER_LEN + 2 * STRIDE];
    assert!(
        open(&v, &id, &key, cut).is_err(),
        "the new last chunk was sealed with final = 0"
    );
}

#[test]
fn appending_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(2 * CS as usize), CS);
    let mut longer = obj.clone();
    longer.extend_from_slice(&obj[OBJECT_HEADER_LEN..OBJECT_HEADER_LEN + STRIDE]); // a copy of chunk 0
    assert!(rejected(&v, &id, &key, &longer));
    let mut junk = obj.clone();
    junk.extend_from_slice(&[0u8; 100]);
    assert!(rejected(&v, &id, &key, &junk));
}

#[test]
fn swapping_chunks_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(3 * CS as usize), CS);
    let c = |i: usize| OBJECT_HEADER_LEN + i * STRIDE..OBJECT_HEADER_LEN + (i + 1) * STRIDE;
    let mut swapped = obj.clone();
    swapped[c(0)].copy_from_slice(&obj[c(1)]);
    swapped[c(1)].copy_from_slice(&obj[c(0)]);
    assert!(rejected(&v, &id, &key, &swapped));
}

#[test]
fn duplicating_a_chunk_over_another_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(3 * CS as usize), CS);
    let mut dup = obj.clone();
    let (from, to) = (
        OBJECT_HEADER_LEN..OBJECT_HEADER_LEN + STRIDE,
        OBJECT_HEADER_LEN + STRIDE..OBJECT_HEADER_LEN + 2 * STRIDE,
    );
    dup[to].copy_from_slice(&obj[from]);
    assert!(rejected(&v, &id, &key, &dup));
}

#[test]
fn removing_a_middle_chunk_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(4 * CS as usize), CS);
    let mut cut = obj[..OBJECT_HEADER_LEN + STRIDE].to_vec();
    cut.extend_from_slice(&obj[OBJECT_HEADER_LEN + 2 * STRIDE..]);
    assert!(rejected(&v, &id, &key, &cut));
}

#[test]
fn wrong_key_object_id_or_vault_is_refused() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(100), CS);
    let other_key = FileKey::generate().unwrap();
    assert!(open(&v, &id, &other_key, &obj).is_err());
    assert!(open(&v, &oid(), &key, &obj).is_err(), "different object id");
    let (v2, _h) = new_vault();
    assert!(open(&v2, &id, &key, &obj).is_err(), "different vault");
}

#[test]
fn changing_the_chunk_size_field_to_another_valid_value_is_detected() {
    let (v, id, key) = setup();
    let obj = seal(&v, &id, &key, &pattern(3 * CS as usize), CS);
    for cs in [MIN_CHUNK_SIZE * 2, MIN_CHUNK_SIZE * 4, 1 << 20] {
        let mut m = obj.clone();
        m[44..48].copy_from_slice(&cs.to_le_bytes());
        assert!(rejected(&v, &id, &key, &m), "chunk size {cs}");
    }
    let mut bad = obj.clone();
    bad[44..48].copy_from_slice(&1000u32.to_le_bytes());
    assert!(open(&v, &id, &key, &bad).is_err());
}

#[test]
fn a_lying_nonce_prefix_is_detected() {
    let (v, id, key) = setup();
    let mut obj = seal(&v, &id, &key, &pattern(100), CS);
    obj[48] ^= 0xff;
    assert!(rejected(&v, &id, &key, &obj));
}

#[test]
fn chunk_size_bounds_are_enforced_when_writing() {
    let (v, id, key) = setup();
    for bad in [
        0u32,
        1000,
        MIN_CHUNK_SIZE - 1,
        3 * MIN_CHUNK_SIZE,
        MAX_CHUNK_SIZE * 2,
    ] {
        assert!(
            ObjectWriter::new(Vec::new(), v.vault_id(), &id, &key, bad).is_err(),
            "{bad}"
        );
    }
    for good in [MIN_CHUNK_SIZE, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE] {
        assert!(
            ObjectWriter::new(Vec::new(), v.vault_id(), &id, &key, good).is_ok(),
            "{good}"
        );
    }
}

#[test]
fn nonce_prefixes_are_unique_and_identical_files_encrypt_differently() {
    let (v, id, key) = setup();
    let mut seen = HashSet::new();
    let data = pattern(500);
    let mut first: Option<Vec<u8>> = None;
    for _ in 0..1000 {
        let obj = seal(&v, &id, &key, &data, CS);
        assert!(seen.insert(obj[48..64].to_vec()), "nonce prefix repeated");
        match &first {
            None => first = Some(obj),
            Some(f) => assert_ne!(f[OBJECT_HEADER_LEN..], obj[OBJECT_HEADER_LEN..]),
        }
    }
}

#[test]
fn garbage_and_foreign_files_are_refused() {
    let (v, id, key) = setup();
    for junk in [
        &b""[..],
        &[0u8; 10][..],
        &[0u8; 200][..],
        &b"PK\x03\x04 not an object at all, just some bytes padding padding padding padding"[..],
    ] {
        assert!(open(&v, &id, &key, junk).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn any_data_and_chunk_size_roundtrips(
        data in proptest::collection::vec(any::<u8>(), 0..20_000),
        cs_pow in 12u32..=14,
        piece in 1usize..5000,
    ) {
        let (v, id, key) = setup();
        let cs = 1u32 << cs_pow;
        let mut w = ObjectWriter::new(Vec::new(), v.vault_id(), &id, &key, cs).unwrap();
        for p in data.chunks(piece) { w.write_all(p).unwrap(); }
        let obj = w.finish().unwrap();
        let mut r = open(&v, &id, &key, &obj).unwrap();
        prop_assert_eq!(r.len(), data.len() as u64);
        prop_assert_eq!(read_all(&mut r).unwrap(), data);
    }

    #[test]
    fn any_single_bit_flip_is_detected(
        data in proptest::collection::vec(any::<u8>(), 0..9_000),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let (v, id, key) = setup();
        let mut obj = seal(&v, &id, &key, &data, CS);
        let i = pos.index(obj.len());
        obj[i] ^= 1 << bit;
        prop_assert!(rejected(&v, &id, &key, &obj));
    }

    #[test]
    fn random_access_matches_slices(
        data in proptest::collection::vec(any::<u8>(), 1..15_000),
        a in any::<prop::sample::Index>(),
        len in 0usize..6_000,
    ) {
        let (v, id, key) = setup();
        let obj = seal(&v, &id, &key, &data, CS);
        let mut r = open(&v, &id, &key, &obj).unwrap();
        let start = a.index(data.len());
        let end = (start + len).min(data.len());
        r.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut got = vec![0u8; end - start];
        r.read_exact(&mut got).unwrap();
        prop_assert_eq!(&got[..], &data[start..end]);
    }
}
