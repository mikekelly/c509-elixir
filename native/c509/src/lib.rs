use rustler::{Env, NifResult, Binary};  // Importing Binary here
use rustler::types::binary::OwnedBinary;
use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::bn::BigNumContext;

rustler::init!("Elixir.C509", [recover_compressed_r1]);

#[rustler::nif]
fn recover_compressed_r1<'a>(env: Env<'a>, binary_data: Binary) -> NifResult<Binary<'a>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|_| rustler::Error::Atom("error_creating_group"))?;

    let mut ctx = BigNumContext::new()
        .map_err(|_| rustler::Error::Atom("error_creating_context"))?;

    let point = EcPoint::from_bytes(&group, binary_data.as_slice(), &mut ctx)
        .map_err(|_| rustler::Error::Atom("error_decoding_point"))?;

    let uncompressed_point_bytes = point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|_| rustler::Error::Atom("error_encoding_point"))?;

    let mut result_bin = OwnedBinary::new(uncompressed_point_bytes.len())
        .ok_or(rustler::Error::Atom("error_allocating_binary"))?;

    result_bin.as_mut_slice().copy_from_slice(&uncompressed_point_bytes);

    // Ensure the Binary is tied to the same lifetime as `env`
    Ok(Binary::from_owned(result_bin, env))
}