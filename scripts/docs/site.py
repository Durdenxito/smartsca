"""Write the landing page; Javadoc and TypeDoc supply the technical reference."""
from pathlib import Path

site = Path('build/site')
site.mkdir(parents=True, exist_ok=True)
(site / '.nojekyll').touch()
(site / 'index.html').write_text('''<!doctype html>
<html lang="es">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SmartSCA — documentación técnica</title>
<main>
  <h1>SmartSCA — documentación técnica</h1>
  <p>Clases, métodos, propiedades y firmas del código actual.</p>
  <ul>
    <li><a href="backend/index.html">Backend Java — Javadoc</a></li>
    <li><a href="frontend/index.html">Frontend TypeScript — TypeDoc</a></li>
  </ul>
  <p>Las descripciones se obtienen de los comentarios Javadoc/TSDoc de las fuentes.</p>
</main>
</html>
''', encoding='utf-8')
