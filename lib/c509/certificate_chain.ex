defmodule C509.CertificateChain do
  def from_bytes(cert_chain_bytes) do
    {:ok, cbor_items} = CBORSequence.items_from_bytes(cert_chain_bytes)
    # error if cbor items length is not divisible by 11
    if rem(Enum.count(cbor_items), 11) != 0 do
      {:error, :invalid_cert_chain_length}
    else
      Enum.chunk_every(cbor_items, 11)
      |> Enum.map(
        fn cbor_items ->
          cbor_items
          |> Enum.map(&CBOR.encode/1)
          |> Enum.join
        end
      )
      |> Enum.map(
        fn cert_bytes ->
          {:ok, cert} = C509.Certificate.from_bytes(cert_bytes)
          cert
        end
      )
    end
  end

  def verify_cert(cert_chain, cert, root_certs) do
    case find_parent_cert(cert_chain, cert) do
      {:ok, parent_cert} ->
        C509.Certificate.verified_by_issuer?(cert, parent_cert.subject_public_key.value) &&
          case Enum.find(root_certs, &(C509.Certificate.to_bytes(parent_cert) == &1)) do
            nil ->
              if parent_cert.issuer == parent_cert.subject do
                {:error, :root_of_chain_not_authoritative}
              else
                C509.CertificateChain.verify_cert(cert_chain, parent_cert, root_certs)
              end
            _ -> {:ok}
          end

      {:error, :parent_cert_not_found} ->
        {:error, :cert_and_chain_did_not_resolve_to_a_root_cert}
    end
  end

  defp find_parent_cert(cert_chain, cert) do
    case cert_chain do
      [] ->
        {:error, :parent_cert_not_found}

      [c | rest] ->
        if c.subject == cert.issuer do
          {:ok, c}
        else
          find_parent_cert(rest, cert)
        end
    end
  end
end
