# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'gostcrypto'
copyright = '2020, Evgeny Drobotun'
author = 'Evgeny Drobotun'

# The full version, including alpha/beta/rc tags
release = '1.2.5'

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#language = 'ru'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Ensure that text wrapping works in a table, by overring some CSS.
# See https://github.com/rtfd/sphinx_rtd_theme/issues/117
def setup(app):
    app.add_stylesheet('theme_overrides.css')

# The suffix of source filenames.
source_suffix = '.rst'

# The encoding of source files.
source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'

latex_elements = {
# The paper size ('letterpaper' or 'a4paper').
#'papersize': 'letterpaper',

# The font size ('10pt', '11pt' or '12pt').
#'pointsize': '10pt',

# Additional stuff for the LaTeX preamble.
'preamble': '\\usepackage[utf8]{inputenc}',
#'babel': '\\usepackage[russian]{babel}',
'cmappkg': '\\usepackage{cmap}',
'fontenc': '\usepackage[T1,T2A]{fontenc}',
'utf8extra':'\\DeclareUnicodeCharacter{00A0}{\\nobreakspace}',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
  ('index', 'Sphinx.tex', 'GOST cryptographic function',
   'Drobotun Evgeny', 'manual'),
]
