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

  test "verify to be signed cert is generated correctly" do
    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    expected_tbs_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB0100"
    cert_bytes = Base.decode16!(cert_hex)
    expected_tbs_bytes = Base.decode16!(expected_tbs_hex)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.to_be_signed_bytes(cert) == expected_tbs_bytes
  end

  test "verify against public key" do
    issuer_private_key_hex = "DC66B3415456D649429B53223DF7532B942D6B0E0842C30BCA4C0ACF91547BB2"
    issuer_private_key_bytes = Base.decode16!(issuer_private_key_hex)
    {issuer_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1, issuer_private_key_bytes)

    cert_hex = "004301F50D6B52464320746573742043411A63B0CD001A6955B90047010123456789AB01582102B1216AB96E5B3B3340F5BDF02E693F16213A04525ED44450B1019C2DFD3838AB010058406FC903015259A38C0800A3D0B2969CA21977E8ED6EC344964D4E1C6B37C8FB541274C3BB81B2F53073C5F101A5AC2A92886583B6A2679B6E682D2A26945ED0B2"
    cert_bytes = Base.decode16!(cert_hex)

    {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)

    assert C509.Certificate.verify(cert, issuer_public_key)
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

    assert C509.Certificate.verify(cert, public_key)
  end
end
