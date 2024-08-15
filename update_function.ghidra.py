from ghidra.program.model.symbol import SourceType

from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Edge
from ghidra.util.graph import Vertex

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.flatapi import FlatProgramAPI

from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.data import DataTypeConflictHandler

import httplib
import json
import Queue

# Get needed objects
dtm = currentProgram.getDataTypeManager()
hfdu = HighFunctionDBUtil()

# Get flat program api for current program
fpapi = FlatProgramAPI(currentProgram)
fm = currentProgram.getFunctionManager()

# Init decompiler
ifc = DecompInterface()
options = DecompileOptions()
ifc.setOptions(options)
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

# Get address of offset
def getAddress(offset):
	return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

# Recovers structs
def recover_struct_request(cCode):
	conn = httplib.HTTPConnection('localhost:8000')
	conn.request('POST', '/api/structs', str(cCode), {"content-type": "text/plain"})
	response = conn.getresponse()
	return json.loads(response.read())

# Recovers final pass
def recover_c_request(cCode):
	conn = httplib.HTTPConnection('localhost:8000')
	conn.request('POST', '/api/rev', str(cCode), {"content-type": "text/plain"})
	response = conn.getresponse()
	return json.loads(response.read())

# Preprocess a function through our multi-stage process
def preprocess_function(func):
	# Get the function and decompile it
#	func = getGlobalFunctions(funcName)[0]
	decompilerResult = ifc.decompileFunction(func, 60, monitor)
	decompiledC = decompilerResult.getDecompiledFunction().getC()
	# Make sure the function is long enough to be worth fully reverse engineering (and not just recovering names from)
	# Also, don't reverse engineer functions that already have names
	symbol = func.getSymbol()
	if not symbol.getName().startswith("FUN_"): # Doesn't start with FUN_? Don't reverse engineer it. (TODO: Still reverse engineer it, just don't override the name)
		return
	if decompiledC.count(';') < 5:
		symbol.setName("SHORT_" + symbol.getName(), SourceType.ANALYSIS)
		return # Too short!
	# Add variables/structs to the function
	high_func = decompilerResult.getHighFunction()
	symbols = {}
	for symbol in high_func.getLocalSymbolMap().getSymbols():
		symbols[symbol.getName()] = symbol
	structResults = recover_struct_request(decompiledC)
	# Add structs. TODO: Add the structs to something function-specific so we can merge them later
	for structDef in structResults["structs"]:
		parser = CParser(data_type_manager)
		parsed_datatype = parser.parse(structDef)
		datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)
	# Add vars
	for oldName, newName, newDataType in structResults["vars"]:
		try:
#			hfdu.updateDBVariable(symbols[symbol], "varB", dtm.getDataType("int"), SourceType.USER_DEFINED)
			hfdu.updateDBVariable(symbols[oldName], newName, dtm.getDataType(newDataType), SourceType.ANALYSIS)
		except KeyError:
			pass
	# Re-decompile the function
	decompilerResult = ifc.decompileFunction(func, 60, monitor) # TODO: Is this necessary?
	decompiledC = decompilerResult.getDecompiledFunction().getC()
	# Preprocess the function further for a final result
	finalResult = recover_c_request(decompiledC)
	fpapi.setPlateComment(func.getEntryPoint(), finalResult["c"])
	# Set function name. Signature is less important because 
	func.getSymbol().setName(finalResult["name"], SourceType.ANALYSIS)
	# Set function signature. TODO: Implement
#	ApplyFunctionSignatureCmd

# Gets function call graph of a program
def get_function_call_graph(prog):
	# Create function call graph
	digraph = DirectedGraph()
	listing = prog.getListing()
	funcs = fm.getFunctions(True) # True means iterate forward
	# Iterate over all functions, adding them as vertexes and their calls as edges
	for func in funcs: 
		# Add function vertices
		print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint())) # FunctionDB
		digraph.add(Vertex(func))
		# Add edges for static calls
		entryPoint = func.getEntryPoint()
		instructions = listing.getInstructions(entryPoint, True)
		for instruction in instructions:
			addr = instruction.getAddress()
			oper = instruction.getMnemonicString()
			if oper == "CALL":
				print("    0x{} : {}".format(addr, instruction))
				flows = instruction.getFlows()
				if len(flows) == 1:
					target_addr = "0x{}".format(flows[0])
					digraph.add(Edge(Vertex(func.getEntryPoint()), Vertex(getAddress(target_addr))))
	# Return result
	return digraph

# Run full preprocessing on all functions
if __name__ == "__main__":
	# Get function call graph
	digraph = get_function_call_graph(currentProgram)
	# Get the symbol table of the current program
	symtab = currentProgram.getSymbolTable()
	# Get all external entry points.
	# This is an iterator of addresses for exports.
	exportAddrs = set(symtab.getExternalEntryPointIterator())
## Iterate the entry point addresses to get the relative symbol.
## Print the symbol name if successfully got.
#for addr in exportAddrs:
#    sym = sm.getPrimarySymbol(addr)
#    if(sym is not None):
#        print(sym.getName())
#
#print("DiGraph info:")
#edges = digraph.edgeIterator()
#while edges.hasNext():
#	edge = edges.next()
#	from_vertex = edge.from()
#	to_vertex = edge.to()
#	print("  Edge from {} to {}".format(from_vertex, to_vertex))
#
#vertices = digraph.vertexIterator()
#while vertices.hasNext():
#	vertex = vertices.next()
#	print("  Vertex: {} (key: {})".format(vertex, vertex.key()))
	# Set up BFS down the graph to make them into a list in the reverse of the order we want to analyze them
	toCrawl = Queue.Queue()
	crawled = set()
	toAnalyze = []
	for addr in exportAddrs:
		currentFunc = fm.getFunctionAt(addr)
		if currentFunc is not None:
			toCrawl.put(currentFunc.getEntryPoint())
			crawled.add(currentFunc.getEntryPoint())
	# Crawl the functions to get the reverse of the order we want to analyze them
	while not toCrawl.empty():
		currentAddr = toCrawl.get()
		if currentAddr is not None:
			currentFunc = fm.getFunctionAt(currentAddr)
			if not currentFunc.thunk and not currentFunc.external:
				toAnalyze.append(currentFunc)
			for currentVertex in digraph.getVerticesHavingReferent(currentAddr):
				for nextVertex in sorted(digraph.getChildren(currentVertex), key=lambda x: x.referent()):
					nextAddr = nextVertex.referent()
					if nextAddr not in crawled:
						toCrawl.put(nextAddr)
						crawled.add(nextAddr)
	# Reverse the order and analyze the functions in that order
	# NOTE: We should probably ensure that all functions are not empty and not compiler-generated (so we don't need to make as many calls to the AI)
	for func in toAnalyze[::-1]:
		preprocess_function(func)