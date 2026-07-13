import Lean.Environment
import Lean.CoreM
import Lean.Util.CollectAxioms
import Lean.Data.Json

open Lean

private def axiomRecord (theoremName : String) (axioms : Array Name) : Json :=
  Json.mkObj [
    ("theorem", Json.str theoremName),
    ("axioms", Json.arr (axioms.map fun name => Json.str name.toString))
  ]

private def auditTheorem (env : Environment) (theoremName : String) : IO Json := do
  let name := theoremName.toName
  if name.isAnonymous || (env.find? name).isNone then
    throw <| IO.userError s!"unknown theorem: {theoremName}"
  let action : Lean.CoreM (Array Name) := Lean.collectAxioms name
  let axioms <- action.toIO'
    { fileName := "hegemon-axiom-audit", fileMap := default }
    { env }
  return axiomRecord theoremName axioms

unsafe def main (args : List String) : IO UInt32 := do
  let (theoremListPath, moduleName) <- match args with
    | [theoremListPath] => pure (theoremListPath, "Hegemon")
    | [theoremListPath, moduleName] => pure (theoremListPath, moduleName)
    | _ => throw <| IO.userError "usage: lean_axiom_audit.lean <theorem-list> [module]"

  initSearchPath (← findSysroot)
  let module := moduleName.toName
  if module.isAnonymous then
    throw <| IO.userError s!"invalid module name: {moduleName}"

  -- Import constants without loading contributor-defined environment extensions or plugins.
  let env <- importModules
    (loadExts := false)
    (level := OLeanLevel.private)
    #[{ module }]
    {}
    0
    #[]

  let contents <- IO.FS.readFile theoremListPath
  let theoremNames := contents.splitOn "\n"
    |>.map (fun line => line.trimAscii.toString)
    |>.filter (fun line => !line.isEmpty)
  if theoremNames.isEmpty then
    throw <| IO.userError "theorem list is empty"
  let records <- theoremNames.toArray.mapM (auditTheorem env)
  IO.println (Json.arr records).compress
  return 0
