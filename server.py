"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses.

 Matt Scheirer, 2013
 This is a very primitive bottle based request server to run on a heroku box 
 and serve access to an sql database. The users and passwords are intentionally
 hardcoded to restrict access since this is a demonstration.
 
 See requirements.txt and runtime.txt for the various dependencies this was written against.
"""

from bottle import post, request, response, run
from random import choice
from time import time
from multiprocessing import cpu_count
from os import environ
import psycopg2
import re
import string
import atexit

# DON'T store passwords in plaintext. In a produciton environment these would be
# stored in an encrypted database or file, preferrably 256 bit AES in case any sql 
# vulnerabilities emerge to inject queries.
users = {
  'matt' : 'bdm4Xj8uHjd7654l',
  'guest' : 'ExtremeMeasures',
}

# Neat feature of bottle - dict returns from http requests generate json content-types 
# and implicitly does the dumps. These dicts are json returns of common errors.
badValidate = {'status' : 'Invalid Credentials'}
badJSON = {'status' : 'Invalid JSON'}
noCmd = {'status' : 'No sql command'}

"""
 Regex patterns to identify SQL commands passed in. All use re.I to be case insenitive regexes.
 The following statements aren't included:
 PREPARE / EXECUTE : break the discretization of statements I have going.
 REASSIGN OWNED / GRANT / REVOKE : we use one sql user and nobody outside should need to modify one. Note: 
    I don't forbid other cascade user modification commands that are parts of drop, alter, or add, in practice 
    you would sanitize this more. I just didn't need to add this one if it has no practical use.
 BEGIN / COMMIT / ABORT / ROLLBACK / DEALLOCATE / LOCK / RELEASE SAVEPOINT / SAVEPOINT / START TRANSACTION: 
    These block control statements depend on multiple sql instructions happening in order. Since this server allows 
    concurrent users, having these statements would allow other inputs to enter a block statement.
 CHECKPOINT : All statements are immediately commited after use, and logging is inacccessable by users.
 DECLARE / CLOSE / FETCH / MOVE : The database itself is managing the cursor, and clients shouldn't know it's name.
 COPY : all sql statements are over json without files attached.
 DO : why are you trying to execute arbitrary code?
 LISTEN / NOTIFY / UNLISTEN : These commands create callbacks that would break result fetches if they are caused by
    another users listeners in someones query. In a more advanced implementation, you would want to have open 
    connections to clients and allow for event signals like this.
 LOAD : there is undefined behavior in trying to load arbitrary libraries on a heroku dyno.
 SECURITY LABEL : Requires backend handlers of security transactions. Way beyond the scope of this project, and very
    context specific (a use case is for selinux).
"""
queries = (re.compile("ANALYZE", re.I), 
  re.compile("EXPLAIN", re.I),
# I mentioned cascade statements from multiple users can intermingle. This is one of those cases - if two people are
# submitting queries simultaneously, an out of order select can screw things up. To fix it, you would want to force
# users to create block statements with begin etc and buffer statements until a complete block can be submitted to the
# backend. However, selecting is kind of important.
  re.compile("SELECT", re.I),
  re.compile("SHOW", re.I),
  re.compile("VALUES", re.I),
)
mods = (re.compile("ALTER", re.I), 
  re.compile("CLUSTER", re.I),
  re.compile("REINDEX", re.I),
  re.compile("RESET", re.I),
  re.compile("SET", re.I),
  re.compile("UPDATE", re.I),
  re.compile("VACUUM", re.I),
)
adds = (re.compile("CREATE", re.I), 
  re.compile("INSERT", re.I), 
)
# These are the destructive commands that can screw up a database.
dangers = (re.compile("DELETE", re.I), 
  re.compile("DROP", re.I), 
  re.compile("TRUNCATE", re.I),
)

# It would be reasonable in a production environment to replace all those re.compile({}, re.I) statements with a
# delegate like:
# def compWrap(regex):
#    return re.compile(regex, re.I)
# Depending on if it is used a lot. Here it is just clearer to use the standard library regex syntax repeatedly.

secretkey = 'itsasecrettoeverybody-'.join(choice(string.ascii_letters + string.digits) for i in range(32))

def validUser(usr, pwd):
  if usr in users and users[usr] == pwd:
    return True
  return False

# Composition, not polymorphism! These are all the input santiziation measures on a user input.
# validCmds is the set of sql statements authorized to be run.
def verifyRequest(request, validCmds):
  if request.get_cookie('session', secret=secretkey) not in users:
    return (False, badValidate)
  query = request.json
  if query == None:
    return (False, badJSON)
# The posted JSON must have the statement as the key : value of cmd : statement.
  cmd = query['cmd']
  if cmd == None:
    return (False, noCmd)
  for regex in validCmds:
    if regex.match(cmd):
# This partition makes sure we only ever execute one sql statement at a time. Otherwise any
# santization of the first statement is pointless because you could just ; DROP TABLE.
      return (True, cmd.partition(';')[0])
  return (False, {"status" : "badCommand : " + cmd})

# Extracted the behavior of queries that modify the db.
def runmod(request, validCmds):
  status = verifyRequest(request, validCmds)
  if not status[0]:
    return status[1]
#  db = psycopg2.connect(database='datjsbtecref3n', 
#    host='ec2-54-243-200-16.compute-1.amazonaws.com', port=5432,
#    user='fesbqrrveoiunr', password='C_W31yYcSP2qqPdEPUDmjnXZqh')
  cursor = db.cursor()
  try:
    cursor.execute(status[1])
    db.commit()
# Paranoid safety here, I rollback transactions even if its per-commit and an error means it never
# finished. I'd rather be safe than sorry.
  except psycopg2.Warning as msg:
    db.rollback()
    return {'warning' : str(msg)}
  except psycopg2.Error as msg:
    db.rollback()
    return {'error' : msg.pgerror}
  finally:
    cursor.close()
#    db.close()
  return {'result' : 'Transaction Success'}

@post('/')
@post('/login')
def login():
  query = request.json
  if query == None:
    return badJSON
  usr = query['usr']
# In production, you would want clients to encrypt the password with a publickey before sending it.
  pwd = query['pwd']
  if not validUser(usr, pwd):
    return badValidate
# In practice, you would want expiring cookies. I figure skip the hassle for a demo.
  response.set_cookie('session', usr, secret=secretkey)
  return {'status' : 'Login success at ' + str(time()) + ' UNIX time'}

# These three all have similar behaviour, since they have side effects, they just have different 
# valid command lists.
@post('/modify')
def modify():
  return runmod(request, mods)
  
@post('/add')
def add():
  return runmod(request, adds)

@post('/remove')
def remove():
  return runmod(request, dangers)

# This is the exception, where queries don't have side effects, so no commits needed.
@post('/query')
def query():
  status = verifyRequest(request, queries)
  if not status[0]:
    return status[1]
#  db = psycopg2.connect(database='datjsbtecref3n', 
#    host='ec2-54-243-200-16.compute-1.amazonaws.com', port=5432,
#    user='fesbqrrveoiunr', password='C_W31yYcSP2qqPdEPUDmjnXZqh')
  cursor = db.cursor()
  try:
    cursor.execute(status[1])
    result = cursor.fetchmany()
  except psycopg2.Warning as msg:
    return {'warning' : str(msg)}
  except psycopg2.Error as msg:
    return {'error', msg.pgerror}
  finally:
    cursor.close()
#    db.close()
  return {'result' : result}

# Documentation says you can use with X as Y syntax with connect and cursor, but in practice
# they error out with __exit__ failing. Potential bug to be submitted against psycopg.
# The host / user / password are all provided by herokus postgres backend.
db = psycopg2.connect(database='datjsbtecref3n', 
  host='ec2-54-243-200-16.compute-1.amazonaws.com', port=5432,
  user='fesbqrrveoiunr', password='C_W31yYcSP2qqPdEPUDmjnXZqh')
#cursor = db.cursor()

# I wish lambdas supported multiple statements.
def closedb():
#  cursor.close()
  db.close()
atexit.register(closedb)

run(server='gunicorn', 
# These options are all required to set up ssl on a heroku dyno and get correct port handling.
  host='0.0.0.0', port=int(environ.get('PORT', 9876)), workers=cpu_count(),
  forwarded_allow_ips='*',
  secure_scheme_headers={'X-FORWARDED-PROTOCOL': 'ssl', 'X-FORWARDED-PROTO': 'https', 'X-FORWARDED-SSL': 'on'}
)
