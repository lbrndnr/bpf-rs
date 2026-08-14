use crate::{
    OpenObject,
    libbpf::{
        Result,
        skel::{OpenSkel, Skel, SkelBuilder},
    },
};
use std::marker::PhantomData;

pub struct Program<
    'obj,
    SB: SkelBuilder<'obj, Output = OS>,
    OS: OpenSkel<'obj, Output = S>,
    S: Skel<'obj>,
> {
    obj_marker: PhantomData<&'obj ()>,
    sb_marker: PhantomData<SB>,
    os_marker: PhantomData<OS>,
    pub skel: S,
}

impl<'obj, SB: SkelBuilder<'obj, Output = OS>, OS: OpenSkel<'obj, Output = S>, S: Skel<'obj>>
    Program<'obj, SB, OS, S>
{
    pub fn build(builder: SB, obj: &'obj mut OpenObject) -> Result<Program<'obj, SB, OS, S>> {
        let open_skel = builder.open(obj)?;
        let skel = open_skel.load()?;

        let prog = Program {
            obj_marker: PhantomData,
            sb_marker: PhantomData,
            os_marker: PhantomData,
            skel,
        };

        Ok(prog)
    }
}
