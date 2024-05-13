defmodule C509Test do
  use ExUnit.Case
  doctest C509

  test "basic cbor sequence parsing" do
    cbor_sequence_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cbor_sequence_bytes = Base.decode16!(cbor_sequence_hex)
    {:ok, items} = CBORSequence.items_from_bytes(cbor_sequence_bytes)
    assert length(items) == 11
  end

  test "basic certificate parsing" do
    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cert_bytes = Base.decode16!(cert_hex)
    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)
    assert cert.type == 0
    assert cert.serial_number.value == <<0x01F50D::24>>
    assert cert.issuer == "RFC test CA"
    assert cert.valid_not_before == 1672531200
    assert cert.valid_not_after == 1767225600
    assert cert.subject.value == <<0x010123456789AB::56>>
    assert cert.subject_public_key_algorithm == 1
    assert cert.subject_public_key.value == <<0x02B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB::264>>
    assert cert.extensions == 1
    assert cert.issuer_signature_algorithm == 0
    assert cert.issuer_signature.value == <<0x6FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2::512>>
  end

  test "certificate encode and decode round trip" do
    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cert_bytes = Base.decode16!(cert_hex)
    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)
    cert_bytes_round_trip = C509.Certificate.to_bytes(cert)
    assert cert_bytes == cert_bytes_round_trip
  end

  test "verify to be signed cert is generated correctly" do
    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    expected_tbs_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB0100"
    cert_bytes = Base.decode16!(cert_hex)
    expected_tbs_bytes = Base.decode16!(expected_tbs_hex)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.to_be_signed_bytes(cert) == expected_tbs_bytes
  end

  test "verify pre cooked cert from the spec against issuer public key" do
    issuer_private_key_hex = "DC66B3415456D649429B53223DF7532B942D6B0E0842C30BCA4C0ACF91547BB2"
    issuer_private_key_bytes = Base.decode16!(issuer_private_key_hex)
    {issuer_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1, issuer_private_key_bytes)

    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cert_bytes = Base.decode16!(cert_hex)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.verified_by_issuer?(cert, issuer_public_key)
  end

  test "verify public key decoding" do
    subject_private_key_hex = "D718111F3F9BD91B92FF6877F386BDBFCEA7154268FD7F2FB56EE17D99EA16D4"
    subject_private_key_bytes = Base.decode16!(subject_private_key_hex)
    {subject_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1, subject_private_key_bytes)

    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cert_bytes = Base.decode16!(cert_hex)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    decoded_public_key = C509.recover_compressed_r1(cert.subject_public_key.value)
    assert decoded_public_key == subject_public_key
  end

  test "public key compression round trip" do
    {subject_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)
    assert subject_public_key == C509.compress_r1(subject_public_key) |> C509.recover_compressed_r1
  end

  test "mint a new certificate and verify it against the issuer public key" do
    # generate key pair
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "RFC test CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: <<0x010123456789AB::56>>,
      subject_public_key_algorithm: 1,
      subject_public_key: <<0x02B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB::264>>,
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    cert_bytes = C509.ToBeSignedCertificate.mint_certificate(tbs_cert, private_key)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.verified_by_issuer?(cert, public_key)
  end

  test "legit self signed cert can be minted" do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Self-signer",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Self-signer",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    cert_bytes = C509.ToBeSignedCertificate.mint_certificate(tbs_cert, private_key)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.verified_by_issuer?(cert, public_key)
  end

  test "a certificate chain ending at a root cert verifies a leaf cert" do
    {root_public_key, root_private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    root_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Root CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Root CA",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(root_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    root_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(root_tbs_cert, root_private_key)

    {:ok, root_cert} = C509.Certificate.from_bytes(root_cert_bytes)

    {intermediate_public_key, intermediate_private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    intermediate_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Root CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Intermediate CA",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(intermediate_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    intermediate_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(intermediate_tbs_cert, root_private_key)

    {:ok, intermediate_cert} = C509.Certificate.from_bytes(intermediate_cert_bytes)

    {leaf_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)

    leaf_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Intermediate CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Leaf cert",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(leaf_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    leaf_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(leaf_tbs_cert, intermediate_private_key)

    {:ok, leaf_cert} = C509.Certificate.from_bytes(leaf_cert_bytes)

    assert {:ok} == C509.CertificateChain.verify_cert([root_cert, intermediate_cert, leaf_cert], leaf_cert, [root_cert_bytes])
  end

  test "a certificate chain ending at a non-authoritive root cert doesn't verify a leaf cert" do
    {root_public_key, root_private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    root_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Root CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Root CA",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(root_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    root_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(root_tbs_cert, root_private_key)

    {:ok, root_cert} = C509.Certificate.from_bytes(root_cert_bytes)

    {intermediate_public_key, intermediate_private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    intermediate_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Root CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Intermediate CA",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(intermediate_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    intermediate_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(intermediate_tbs_cert, root_private_key)

    {:ok, intermediate_cert} = C509.Certificate.from_bytes(intermediate_cert_bytes)

    {leaf_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)

    leaf_tbs_cert = %C509.ToBeSignedCertificate{
      type: 0,
      serial_number: <<0x01F50D::24>>,
      issuer: "Intermediate CA",
      valid_not_before: 1672531200,
      valid_not_after: 1767225600,
      subject: "Leaf cert",
      subject_public_key_algorithm: 1,
      subject_public_key: C509.compress_r1(leaf_public_key),
      extensions: 1,
      issuer_signature_algorithm: 0
    }

    leaf_cert_bytes = C509.ToBeSignedCertificate.mint_certificate(leaf_tbs_cert, intermediate_private_key)

    {:ok, leaf_cert} = C509.Certificate.from_bytes(leaf_cert_bytes)

    assert C509.CertificateChain.verify_cert([root_cert, intermediate_cert, leaf_cert], leaf_cert, []) == {:error, :root_of_chain_not_authoritative}
  end

  test "verifies precooked certificate and chain" do
    cert_chain_bytes = Base.decode16!("00410170726f6f742e6578616d706c652e636f6d1a63b0cd001a6955b90070726f6f742e6578616d706c652e636f6d01582103d07795e360e635957972d8a0d39e0c279a6adb73874dc9106f48b7799b805d1a010058406222f95184cf27f37ad51c14f48a18f576c0a8275a60daf5c5f2a0362d90510f7cd88bf8dedfca3e1446153a53ae5b273dcfb8fcad206d6b93a3d894a6d8847200410270726f6f742e6578616d706c652e636f6d1a63b0cd001a6955b9007818696e7465726d6564696172792e6578616d706c652e636f6d015821031ec6282a201ae0283184f1c77bec6da9ed4a956f7ad2ea5d5980ee3abc21e02901005840a123e0bf65935bd2e8676dcc202844a0329716a2a9ebd597c477964893a83642c54f9587ac138b5877fcefbd27e40154a3e5ec74f8ebf036cee240c0aa8bfccb0041017818696e7465726d6564696172792e6578616d706c652e636f6d1a63b0cd001a6955b900716578616d706c653a757365723a3132333401582103611a3cf64a996586af402a49e44259703799dec191e52ceb74dc1f3c995e8b1d01005840bdbbbb38353fd7d85a17e178985c7bd08ccdce56f1e5c94a257aa6fa1541c3df6f6b960ddb0c1837b7a0b7cb6f97eac258015845f6f1686e735b25f6e9f204a2", case: :lower)
    cert_bytes = Base.decode16!("0041017818696e7465726d6564696172792e6578616d706c652e636f6d1a63b0cd001a6955b900716578616d706c653a757365723a3132333401582103611a3cf64a996586af402a49e44259703799dec191e52ceb74dc1f3c995e8b1d01005840bdbbbb38353fd7d85a17e178985c7bd08ccdce56f1e5c94a257aa6fa1541c3df6f6b960ddb0c1837b7a0b7cb6f97eac258015845f6f1686e735b25f6e9f204a2", case: :lower)
    root_cert_bytes = Base.decode16!("00410170726f6f742e6578616d706c652e636f6d1a63b0cd001a6955b90070726f6f742e6578616d706c652e636f6d01582103d07795e360e635957972d8a0d39e0c279a6adb73874dc9106f48b7799b805d1a010058406222f95184cf27f37ad51c14f48a18f576c0a8275a60daf5c5f2a0362d90510f7cd88bf8dedfca3e1446153a53ae5b273dcfb8fcad206d6b93a3d894a6d88472", case: :lower)

    cert_chain = C509.CertificateChain.from_bytes(cert_chain_bytes)
    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert {:ok} == C509.CertificateChain.verify_cert(cert_chain, cert, [root_cert_bytes])
  end

  test "rejects precooked certificate and chain if no root matches" do
    cert_chain_bytes = Base.decode16!("00410170726f6f742e6578616d706c652e636f6d1a63b0cd001a6955b90070726f6f742e6578616d706c652e636f6d01582103d07795e360e635957972d8a0d39e0c279a6adb73874dc9106f48b7799b805d1a010058406222f95184cf27f37ad51c14f48a18f576c0a8275a60daf5c5f2a0362d90510f7cd88bf8dedfca3e1446153a53ae5b273dcfb8fcad206d6b93a3d894a6d8847200410270726f6f742e6578616d706c652e636f6d1a63b0cd001a6955b9007818696e7465726d6564696172792e6578616d706c652e636f6d015821031ec6282a201ae0283184f1c77bec6da9ed4a956f7ad2ea5d5980ee3abc21e02901005840a123e0bf65935bd2e8676dcc202844a0329716a2a9ebd597c477964893a83642c54f9587ac138b5877fcefbd27e40154a3e5ec74f8ebf036cee240c0aa8bfccb0041017818696e7465726d6564696172792e6578616d706c652e636f6d1a63b0cd001a6955b900716578616d706c653a757365723a3132333401582103611a3cf64a996586af402a49e44259703799dec191e52ceb74dc1f3c995e8b1d01005840bdbbbb38353fd7d85a17e178985c7bd08ccdce56f1e5c94a257aa6fa1541c3df6f6b960ddb0c1837b7a0b7cb6f97eac258015845f6f1686e735b25f6e9f204a2", case: :lower)
    cert_bytes = Base.decode16!("0041017818696e7465726d6564696172792e6578616d706c652e636f6d1a63b0cd001a6955b900716578616d706c653a757365723a3132333401582103611a3cf64a996586af402a49e44259703799dec191e52ceb74dc1f3c995e8b1d01005840bdbbbb38353fd7d85a17e178985c7bd08ccdce56f1e5c94a257aa6fa1541c3df6f6b960ddb0c1837b7a0b7cb6f97eac258015845f6f1686e735b25f6e9f204a2", case: :lower)

    cert_chain = C509.CertificateChain.from_bytes(cert_chain_bytes)
    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert {:error, :root_of_chain_not_authoritative} == C509.CertificateChain.verify_cert(cert_chain, cert, [])
  end
end
