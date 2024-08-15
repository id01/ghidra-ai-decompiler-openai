from flask import Flask, request
import random # for now
import pymongo # Caching

from clang_integration import get_function_fully_qualified

app = Flask(__name__)

# Init caching DB
client = pymongo.MongoClient("mongodb://localhost")
db_cache = client["decompiler"]["cache"]
db_cache.create_index("input", unique=True)

# Init openai api
from openai import OpenAI
client = OpenAI()

@app.route('/api/structs', methods=["POST"])
def predict_structs():
#	request.data == ""
	return {'structs': '', 'vars': ''}

INSTRUCTION_PROMPT = "Convert this decompiled code back into its original precompiled form, adding any custom structs, readable variable names, and comments that may have been removed by the compiler. Do not refactor the code if possible. Remove stack canary protections and other compiler generated constructs. Only provide one function definition, any unknown global variable defintions, and any custom struct defintions. Do not provide any other function definitions or prototypes other than the one declared in the decompiled code. Do not guess that a function is the main function or any variant of main unless the function name has specified it is.\n"
SYSTEM_PROMPT = "You are an exceptionally intelligent code reverse engineering assistant that consistently simplifies decompiled code back into its readable precompiled form. Decompiled code is an low-level, unreadable, obfuscated form of C code with variable names and comments removed."
def request_rev_from_api(data):
	# Fetch from cache if possible
	result = None
	for doc in db_cache.find({"input": data}):
		result = doc["output"]
	# Request result from API if cache miss
	if result is None:
		# Shell out to GPT
		print("Requesting: ", data)
		response = client.chat.completions.create(
			model="gpt-4-turbo",
			messages=[
				{"role": "system", "content": SYSTEM_PROMPT},
				{"role": "user", "content": INSTRUCTION_PROMPT + "```c\n%s\n```" % data},
			]
		)
		result = response.choices[0].message.content
		# Insert into cache
		db_cache.insert_one({"input": data, "output": result, "seq": 0})
	return result

@app.route('/api/rev', methods=["POST"])
def predict_rev():
	# Get reversed code
	result = request_rev_from_api(request.data.decode('utf-8'))
	# Get name
#	try:
	name = get_function_fully_qualified(result.split('```')[1].split('\n',1)[1])
#	except:
#		name = 'UNKNOWN_FUNC_%d' % random.randint(0, 99999999)
	# Return comment and name
	return {'c': result, 'name': name}

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=8000)
