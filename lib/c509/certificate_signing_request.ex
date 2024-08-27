# implement C509.CertificateSigningRequest.from_bytes(csr_bytes)
defmodule C509.CertificateSigningRequest do
  defstruct [
    :type,
    :subject_signature_algorithm,
    :subject,
    :subject_public_key_algorithm,
    :subject_public_key,
    :extensions,
    :signature
  ]

  def from_bytes(csr_bytes) do
    case CBORSequence.items_from_bytes(csr_bytes) do
      {:ok, [type, subject_signature_algorithm, subject, subject_public_key_algorithm, subject_public_key, extensions, signature]} ->
        {:ok, %__MODULE__{
          type: type,
          subject_signature_algorithm: subject_signature_algorithm,
          subject: subject,
          subject_public_key_algorithm: subject_public_key_algorithm,
          subject_public_key: subject_public_key,
          extensions: extensions,
          signature: signature
        }}
      _ ->
        {:error, :invalid_csr_format}
    end
  end

  def to_bytes(csr) do
    [
      csr.type,
      csr.subject_signature_algorithm,
      csr.subject,
      csr.subject_public_key_algorithm,
      csr.subject_public_key,
      csr.extensions,
      csr.signature
    ]
    |> Enum.map(&CBOR.encode/1)
    |> Enum.join()
  end

  def sign(csr, private_key) do
    unsigned_bytes = to_be_signed_bytes(csr)
    der_encoded_signature = :crypto.sign(
      :ecdsa,
      :sha256,
      unsigned_bytes,
      [private_key, :secp256r1]
    )
    {:ok, signature_bytes} = COSEUtils.encode_der_signature_as_cose(der_encoded_signature)
    signature = %CBOR.Tag{tag: :bytes, value: signature_bytes}
    %__MODULE__{csr | signature: signature}
  end

  def verified_by_subject?(csr, public_key) do
    unsigned_bytes = to_be_signed_bytes(csr)
    :crypto.verify(
      :ecdsa,
      :sha256,
      unsigned_bytes,
      ECDSASignature.new(csr.signature.value) |> ECDSASignature.to_der(),
      [public_key, :secp256r1]
    )
  end

  def to_be_signed_bytes(csr) do
    [
      csr.type,
      csr.subject_signature_algorithm,
      csr.subject,
      csr.subject_public_key_algorithm,
      csr.subject_public_key,
      csr.extensions
    ]
    |> Enum.map(&CBOR.encode/1)
    |> Enum.join()
  end
end
