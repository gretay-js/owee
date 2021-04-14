let read ~(conv:string->'a) (r:'a option ref) i =
  incr i;
  if !i >= Array.length Sys.argv then
    raise (Failure "Missing arguments");
  (match !r with
   | Some _ ->
     raise (Failure "Duplicate argument. Every option must appear at most once.")
   | None ->
     r := Some (conv Sys.argv.(!i)));
  incr i

let readi = read ~conv:int_of_string
let read = read ~conv:Fun.id

let readme () =
  Printf.printf {|
    loc2addr PATH [OPTIONS]

    where PATH is a path to an ELF executable and
    and OPTIONS are
    -file FILE           print only locations in FILE
    -line n              print only location on line N (ignored if -file not set)
    -column N            print only locations on column N (ignored if -line not set)
    -discriminator n     print only locations with N (ignored if -column not set)
    -help                print this message and exit

    Print location information in a format similar to 'readelf --debug-decodedeline'
    but includes column and discriminators.
    Use OPTIONS to print only locations in a particular file, line, column or
    discriminator.

|}

let () =
  let path = ref None in
  let file = ref None in
  let line = ref None in
  let col = ref None in
  let discr = ref None in
  (* ad hoc args parser *)
  if Array.length Sys.argv <= 1 then begin
    prerr_endline ("Usage: " ^ Sys.argv.(0) ^ " my_binary.elf [options]");
    exit 1
  end
  else begin
    let i = ref 1 in
    while !i < Array.length Sys.argv do begin
      match Sys.argv.(!i) with
      | "-help" | "--help" -> readme (); exit 0;
      | "-line" -> readi line i;
      | "-column" -> readi col i;
      | "-discriminator" -> readi discr i;
      | "-file" -> read file i;
      | s ->
        if s.[0] = '-' then
          raise (Failure (Printf.sprintf "Unknown option %s" s));
        match !path with
        | None -> path := Some s; incr i
        | Some _ ->
          raise (Failure "Specify only one ELF executable as argument")
    end
    done
  end;
  let report filename (state:Owee_debug_line.state) =
    let print () =
    Printf.printf "%s\t%d\t%d\t%d\t0x%x\n" filename
      state.line state.col state.discriminator state.address
    in
    match !file with
    | None -> print ()
    | Some file ->
      if String.equal file filename then
        match !line with
        | None -> print ()
        | Some line  ->
          if line = state.line then
            match !col with
            | None -> print ()
            | Some col ->
              if col = state.col then
                match !discr with
                | None -> print ()
                | Some discr ->
                  if discr = state.discriminator then print ()
  in
  let path =
    match !path with
    | None -> raise (Failure "Missing argument: PATH to ELF executable file")
    | Some s -> s
  in
  let buffer = Owee_buf.map_binary path in
  let _header, sections = Owee_elf.read_elf buffer in
  match Owee_elf.find_section sections ".debug_line" with
  | None -> ()
  | Some section ->
    let body = Owee_buf.cursor (Owee_elf.section_body buffer section) in
    let rec aux () =
      match Owee_debug_line.read_chunk body with
      | None -> ()
      | Some (header, chunk) ->
        let check header state () =
          let open Owee_debug_line in
          if not state.end_sequence then
            match get_filename header state with
            | None -> ()
            | Some filename ->
              report filename state
        in
        Owee_debug_line.fold_rows (header, chunk) check ();
        aux ()
    in
    aux ()
