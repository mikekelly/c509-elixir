defmodule C509 do
  use Rustler, otp_app: :c509

  def compress_r1(uncompressed_public_key) do
    case byte_size(uncompressed_public_key) do
      65 ->
        # Remove the prefix (first byte) from the public key
        public_key = binary_part(uncompressed_public_key, 1, byte_size(uncompressed_public_key) - 1)

        # Extract the x-coordinate
        x = binary_part(public_key, 0, 32)

        # Extract the y-coordinate
        y = binary_part(public_key, 32, 32)

        # Extract the y-coordinate last byte
        y_last_byte = :binary.at(y, byte_size(y) - 1)

        # Determine whether the y-coordinate is even or odd
        prefix = case rem(y_last_byte, 2) do
          0 -> <<2>>
          1 -> <<3>>
        end

        # Concatenate prefix and x to obtain the compressed public key
        <<prefix::binary, x::binary>>
      _ -> :public_key_in_wrong_format
    end
  end

  def recover_compressed_r1(_arg1), do: :erlang.nif_error(:nif_not_loaded)
end
