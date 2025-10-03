extern crate embed_resource;

fn main() {
    // Diese Zeile sorgt dafür, dass das build-Skript neu ausgeführt wird, wenn sich das Manifest oder das RC-Skript ändert.
    println!("cargo:rerun-if-changed=cs2_creator.manifest");
    println!("cargo:rerun-if-changed=cs2_creator.rc");
    // Diese Zeile kompiliert das RC-Skript, welches das Manifest einbindet.
    embed_resource::compile("cs2_creator.rc", embed_resource::NONE);
}