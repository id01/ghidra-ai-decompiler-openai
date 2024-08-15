import clang
import clang.cindex
from clang.cindex import CursorKind

def fully_qualified(c):
	if c is None:
		return ''
	elif c.kind == CursorKind.TRANSLATION_UNIT:
		return ''
	else:
		res = fully_qualified(c.semantic_parent)
		if res != '':
			return res + '::' + c.spelling
	return c.spelling

FUNC_CURSOR_KINDS = [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR]
def kind_valid(x):
	try:
		return x.kind in FUNC_CURSOR_KINDS and x.is_definition()
	except ValueError:
		return False

def get_function_fully_qualified(cCode):
	cCode = cCode.encode('utf-8')
	idx = clang.cindex.Index.create()
	tu = idx.parse('tmp.cpp', args=['-std=c++11'], unsaved_files=[('tmp.cpp', cCode)], options=0)#, options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD) # Detailed contains #defines
	funcs = {fully_qualified(x): cCode[x.extent.start.offset : x.extent.end.offset].decode('utf-8') for x in tu.cursor.walk_preorder() if x.extent.start.file is not None and x.extent.start.file.name == 'tmp.cpp' and kind_valid(x)}
	return list(funcs.keys())[0]