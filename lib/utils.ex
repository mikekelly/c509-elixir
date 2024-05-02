defmodule CBORSequence do
  def items_from_bytes("") do
    {:ok, []}
  end

  def items_from_bytes(bytes) do
    {:ok, cbor_item, remaining_bytes} = CBOR.decode(bytes)
    {:ok, remaining_items} = items_from_bytes(remaining_bytes)
    {:ok, [cbor_item | remaining_items]}
  end
end

defmodule ECDSASignature do
  require Record

  Record.defrecord(
    :ecdsa_signature,
    :"ECDSA-Sig-Value",
    Record.extract(:"ECDSA-Sig-Value", from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  def new(r, s) when is_integer(r) and is_integer(s) do
    ecdsa_signature(r: r, s: s)
  end

  def new(raw) when is_binary(raw) do
    size = raw |> byte_size() |> div(2)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>> = raw
    new(r, s)
  end

  # Export to DER binary format, for use with :public_key.verify/4
  def to_der(ecdsa_signature() = signature) do
    :public_key.der_encode(:"ECDSA-Sig-Value", signature)
  end
end

defmodule BinaryUtils do
  def pad_leading(binary, size) when is_binary(binary) do
    padding_size = max(size - byte_size(binary), 0)
    padding = String.duplicate(<<0>>, padding_size)
    padding <> binary
  end
end

defmodule COSEUtils do
  def encode_der_signature_as_cose(der_signature) do
    # The DER signature is a sequence of two integers, r and s, each of which is
    # encoded as a signed big-endian integer. The COSE signature is a CBOR array
    # of two integers, r and s, each of which is encoded as a positive big-endian
    # integer.
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_signature)
    # Convert the integers r and s into big endian binaries
    r_bytes = :binary.encode_unsigned(r, :big)
    s_bytes = :binary.encode_unsigned(s, :big)
    # make both of these the same length by padding the shorter one with leading zeros
    r_bytes = BinaryUtils.pad_leading(r_bytes, byte_size(s_bytes) - byte_size(r_bytes))
    s_bytes = BinaryUtils.pad_leading(s_bytes, byte_size(r_bytes) - byte_size(s_bytes))
    {:ok, r_bytes <> s_bytes}
  end
end
