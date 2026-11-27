-- Allow SolidCraft design containers (.sc/.solidcraft) and CAD mesh/exchange artifacts
-- alongside STEP/GLB in board_artifacts.
ALTER TABLE board_artifacts DROP CONSTRAINT IF EXISTS board_artifacts_kind_check;
ALTER TABLE board_artifacts ADD CONSTRAINT board_artifacts_kind_check CHECK (
  kind IN (
    'pcb_svg',
    'schematic_svg',
    'model_glb',
    'model_step',
    'solidcraft',
    'model_stl',
    'model_3mf',
    'model_iges',
    'model_obj',
    'gerbers_zip',
    'bom_csv',
    'kicad_pcb',
    'kicad_sch',
    'pdf'
  )
);
