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
