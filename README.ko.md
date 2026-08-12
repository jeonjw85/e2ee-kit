[English](README.md) | 한국어

# e2ee-kit

쉬운 Rust용 종단 간 암호화(E2EE) 미니 라이브러리
두 당사자 간 데이터를 종단 간 암호화하는 데 필요한 핵심 암호
모듈을 제공합니다

> **상태: v0.1 — 독립 감사 미실시.** 실제로 사용하기 전에
> [보안 모델](#보안-모델)을 꼭 읽으세요!!

## 기능

- X25519 키페어: 생성, 직렬화, 바이트에서 복원
- 한 번의 키 교환으로 양방향 세션 수립 (HKDF-SHA256 키 파생)
- 랜덤 논스를 사용하는 인증 암호화 — 봉투(envelope)는 그 자체로 완결된
  바이트 배열이라 어떤 전송 계층에서도 안전
- 비밀번호로 보호되는 시크릿 박스와 암호화된 키페어 저장 (Argon2id)

## 시작

```sh
cargo add e2ee-kit
```

### 두 당사자가 메시지 교환하기

```rust
use e2ee_kit::{Keypair, Role, Session};

fn main() -> Result<(), e2ee_kit::Error> {
    // 각 side는 장기 키페어를 생성하고 공개키를 서로 교환합니다
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    // 양쪽 모두 상대의 공개키로 세션을 수립합니다
    // 역할(Role)은 반드시 반대여야 합니다
    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator)?;
    let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder)?;

    let envelope = alice_side.seal(b"hello")?;
    // `envelope`를 아무 전송 계층으로 보냅니다
    assert_eq!(bob_side.open(&envelope)?, b"hello");
    Ok(())
}
```

### 비밀번호로 보호하는 저장

```rust
use e2ee_kit::SecretBox;

fn main() -> Result<(), e2ee_kit::Error> {
    let blob = SecretBox::seal(b"a strong password", b"data at rest")?;
    assert_eq!(SecretBox::open(&blob, b"a strong password")?, b"data at rest");
    Ok(())
}
```

### 키페어 영구 저장

```rust
use e2ee_kit::{decrypt_keypair, encrypt_keypair, Keypair};

fn main() -> Result<(), e2ee_kit::Error> {
    let keypair = Keypair::generate();
    let blob = encrypt_keypair(&keypair, b"key storage password")?;
    // blob을 디스크에 저장
    let restored = decrypt_keypair(&blob, b"key storage password")?;
    assert_eq!(restored.public_key(), keypair.public_key());
    Ok(())
}
```

## 와이어 포맷

메시지 봉투 (`Session::seal` / `Message::seal`), 오버헤드 29바이트:

```text
version (1, = 0x01) | nonce (12, random) | ciphertext | Poly1305 tag (16)
```

시크릿박스 blob (`SecretBox::seal` / `encrypt_keypair`):

```text
version (1, = 0x01) | m_cost (4, BE) | t_cost (4, BE) | p_cost (1)
                    | salt (16, random) | nonce (12, random) | ciphertext + tag
```

version 바이트 / 헤더는 AEAD 추가 인증 데이터(AAD)로 인증,  
랜덤 논스는 메시지마다 OS CSPRNG에서 생성됩니다

## 보안 모델

이 크레이트가 제공하는 점:

- 두 키 보유자 간 메시지의 기밀성, 무결성, 인증
  (X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
- 비밀번호로 보호되는 저장 데이터 박스 (Argon2id + ChaCha20-Poly1305)
- 드롭 시 키 자료 제로화

**이 크레이트가 의도적으로 제공하지 않는 점**:

- **전방 비밀성(Forward secrecy).** 세션은 static-static X25519를 사용합니다.
  장기 비밀키가 유출되면 해당 키로 만든 모든 세션(과거 포함)이 노출됩니다.
  유출이 의심되면 키페어를 교체하세요.
- **키 인증.** 상대의 공개키는 반드시 대역 외 채널로 인증해야 합니다  
  이 크레이트는 자신의 공개키로
  바꿔치기하는 중간자 공격을 탐지하지 못합니다.
- 래칫, 그룹 메시징, 메시지 순서 보장, 중복 제거, 전송 계층 일체

한계:

- 하나의 세션 키로는 대략 2^32개 이하의 메시지만 봉인해야 합니다
  (랜덤 96비트 논스의 birthday bound) 그보다 훨씬 이전에 세션을 재수립하세요
- 8바이트 미만 비밀번호는 거부됩니다
- Argon2id 비용 파라미터는 v0.1에서 고정입니다 (메모리 19 MiB, 2패스)

## MSRV

Rust 1.85, edition 2024. v0.1은 std 전용이며, `no_std` + `alloc`은 이후
추가될 수 있습니다.

## 라이선스

MIT - [LICENSE-MIT](LICENSE-MIT)
