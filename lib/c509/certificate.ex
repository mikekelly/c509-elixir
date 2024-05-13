defmodule C509.Certificate do
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
    :issuer_signature_algorithm,
    :issuer_signature
  ]

  def from_bytes(bytes) do
    {:ok, [type,serial_number,issuer,valid_not_before,valid_not_after, subject, subject_public_key_algorithm, subject_public_key, extensions, issuer_signature_algorithm, issuer_signature]} = CBORSequence.items_from_bytes(bytes)
    {:ok, %C509.Certificate{
      type: type,
      serial_number: serial_number,
      issuer: issuer,
      valid_not_before: valid_not_before,
      valid_not_after: valid_not_after,
      subject: subject,
      subject_public_key_algorithm: subject_public_key_algorithm,
      subject_public_key: subject_public_key,
      extensions: extensions,
      issuer_signature_algorithm: issuer_signature_algorithm,
      issuer_signature: issuer_signature
    }}
  end

  def to_be_signed_bytes(cert) do
    cbor_items = [
      cert.type,
      cert.serial_number,
      cert.issuer,
      cert.valid_not_before,
      cert.valid_not_after,
      cert.subject,
      cert.subject_public_key_algorithm,
      cert.subject_public_key,
      cert.extensions,
      cert.issuer_signature_algorithm
    ]
    # map over the items and encode them as CBOR and reduce them to a list of bytes
    cbor_items
    |> Enum.map(&CBOR.encode/1)
    |> Enum.join
  end

  def to_bytes(cert) do
    cbor_items = [
      cert.type,
      cert.serial_number,
      cert.issuer,
      cert.valid_not_before,
      cert.valid_not_after,
      cert.subject,
      cert.subject_public_key_algorithm,
      cert.subject_public_key,
      cert.extensions,
      cert.issuer_signature_algorithm,
      cert.issuer_signature
    ]
    # map over the items and encode them as CBOR and reduce them to a list of bytes
    cbor_items
    |> Enum.map(&CBOR.encode/1)
    |> Enum.join
  end

  def verified_by_issuer?(cert, public_key) do
    # verify the signed bytes against the issuer signature and public key
    :crypto.verify(
      :ecdsa,
      :sha256,
      to_be_signed_bytes(cert),
      ECDSASignature.new(cert.issuer_signature.value) |> ECDSASignature.to_der(),
      [public_key, :secp256r1]
    )
  end

  def verified_by_authority_cert?(cert, authority_cert) do
    # verify the signed bytes against the issuer signature and public key
    :crypto.verify(
      :ecdsa,
      :sha256,
      to_be_signed_bytes(cert),
      ECDSASignature.new(cert.issuer_signature.value) |> ECDSASignature.to_der(),
      [authority_cert.subject_public_key, :secp256r1]
    )
  end
end
