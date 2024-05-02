defmodule C509.ToBeSignedCertificate do
  defstruct [
    :type,
    :serial_number,
    :issuer,
    :valid_not_before,
    :valid_not_after,
    :subject,
    :subject_public_key_algorithm,
    :subject_public_key,
    :extensions,
    :issuer_signature_algorithm
  ]

  def mint_certificate(tbs_cert, private_key) do
    unsigned_bytes = bytes_to_sign(tbs_cert)
    der_encoded_signature = :crypto.sign(:ecdsa, :sha256, unsigned_bytes, [private_key, :secp256r1])
    {:ok, signature_bytes} = COSEUtils.encode_der_signature_as_cose(der_encoded_signature)
    unsigned_bytes <> CBOR.encode(%CBOR.Tag{tag: :bytes, value: signature_bytes})
  end

  defp bytes_to_sign(tbs_cert) do
    cbor_items = [
      tbs_cert.type,
      tbs_cert.serial_number,
      tbs_cert.issuer,
      tbs_cert.valid_not_before,
      tbs_cert.valid_not_after,
      tbs_cert.subject,
      tbs_cert.subject_public_key_algorithm,
      tbs_cert.subject_public_key,
      tbs_cert.extensions,
      tbs_cert.issuer_signature_algorithm
    ]
    # map over the items and encode them as CBOR and reduce them to a list of bytes
    cbor_items
    |> Enum.map(&CBOR.encode/1)
    |> Enum.join
  end
end
