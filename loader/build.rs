// Copyright (c) 2024 HUTAOSHUSBAND - Wallbangbros.com/FireflyProtector.xyz

extern crate embed_resource;

fn main() {
    println!("cargo:rerun-if-changed=cs2_creator.manifest");
    println!("cargo:rerun-if-changed=cs2_creator.rc");
    embed_resource::compile("cs2_creator.rc", embed_resource::NONE);
}
