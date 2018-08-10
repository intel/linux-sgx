(* 
    Dependency injection plugin to allow custom code generation
    from EDL. CodeGen.ml calls into Plugin.available to check 
    if a plugin available. If a plugin is available, then it calls 
    Plugin.gen_edge_routines to generate custom code. 
    Otherwise, it generates code for Intel(R) SGX  SDK.
*)

type plugin = {
    mutable available: bool;
    mutable gen_edge_routines:
         Ast.enclave_content -> Util.edger8r_params -> unit;
}

(* Instance fields will be populated by Open Enclave *)
let instance = {
    available = false;
    gen_edge_routines = fun ec ep -> Printf.printf "Plugin not loaded.\n"
}

let available () = instance.available
let gen_edge_routines ec ep = instance.gen_edge_routines ec ep
