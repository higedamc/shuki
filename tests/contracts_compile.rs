//! Pins the nostr / nostr-sdk 0.44 API surface the leaves rely on.
//! If a dependency bump breaks a name, it breaks HERE first — in one place.

use nostr::{EventBuilder, Filter, Keys, Kind, Tag};
use shuki::signer::Signer;
use shuki::sync::payload::ENTRY_KIND;
use shuki::testutil::MockSigner;

#[test]
fn kind_tag_filter_builder_surface() {
    assert_eq!(Kind::ApplicationSpecificData.as_u16(), ENTRY_KIND);
    let keys = Keys::generate();
    let _filter = Filter::new()
        .author(keys.public_key())
        .kind(Kind::ApplicationSpecificData);
    let unsigned = EventBuilder::new(Kind::ApplicationSpecificData, "ciphertext")
        .tag(Tag::identifier("dtag"))
        .build(keys.public_key());
    assert_eq!(unsigned.kind, Kind::ApplicationSpecificData);
}

#[tokio::test]
async fn mock_signer_nip44_roundtrip_and_signing() {
    let s = MockSigner::new();
    let pk = s.public_key().await.unwrap();

    let ct = s.nip44_encrypt(&pk, b"hello nip44").await.unwrap();
    let pt = s.nip44_decrypt(&pk, &ct).await.unwrap();
    assert_eq!(&*pt, b"hello nip44");

    let unsigned = EventBuilder::new(Kind::ApplicationSpecificData, ct)
        .tag(Tag::identifier("dtag"))
        .build(pk);
    let ev = s.sign_event(unsigned).await.unwrap();
    ev.verify().unwrap();
}

#[tokio::test]
async fn conversation_key_surface() {
    let s = MockSigner::new();
    let ck = s.self_conversation_key().await.unwrap();
    // Pin: as_bytes() exposes the 32-byte key for tagkey derivation.
    assert_eq!(ck.as_bytes().len(), 32);
}

#[test]
fn sdk_client_construction_surface() {
    use nostr_sdk::prelude::*;
    // Construction only — no network IO in this test.
    let conn = Connection::new().proxy("127.0.0.1:9050".parse().unwrap());
    let opts = ClientOptions::new().connection(conn);
    let _client = Client::builder().opts(opts).build();
}
