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
 
 This script was written against Bottle 0.11 and Python 3.3
"""

from bottle import post, request, response
from random import choice
from time import time
import string

# DON'T store passwords in plaintext. In a produciton environment these would be
# stored in an encrypted database or file, preferrably 256 bit blowfish or AES in 
# case any sql vulnerabilities emerge to inject queries.

users = {
  'matt' : 'ExplosiveSheep',
  'guest' : 'AbrahamLincoln',
}

# Neat feature of bottle - dict returns from http requests generate json content-types 
# and implicitly does the dumps. These two dicts are json returns of common errors.
failedValidate = {'Querystatus' : 'Invalid Credentials'}
failedJSON = {'Querystatus' : 'Invalid JSON'}

secretkey = 'itsasecrettoeverybody-'.join(choice(string.ascii_letters + string.digits) for i in range(32))

def validUser(usr, pwd):
  if usr in users and users[usr] == pwd:
    return True
  return False

# Composition, not polymorphism!
def badRequest(request):
  if request.get_cookie('session', secret=secretkey) not in users:
    return (True, failedValidate)
  query = request.json
  if query == None:
    return (True, failedJSON)
# All these tuples are in case we do get a valid query, we can return it and not need to do a (potentially)
# expensive reparse of json data.
  return (False, query)
  
@post('/')
@post('/login')
def login():
  query = request.json
  if query == None:
    return failedJSON
  usr = query['usr']
# In production, you would want clients to encrypt the password with a publickey before sending it.
  pwd = query['pwd']
  if not validUser(usr, pwd):
    return failedValidate
# In practice, you would want expiring cookies, and two cookies per user - a session cookie
# to verify the user identity, and a user specific key cookie to guarantee no one is trying
# to impersonate someone else logged in who knows the secretkey. Bottle supports cookie expiration.
  response.set_cookie('session', usr, secret=secretkey)
  return {'Querystatus' : 'Login success at ' + str(time()) + 'UNIX time')}

@post('/query')
def query():
  status = badRequest(request)
  if status[0] not False:
    return status
  query = status[1]

@post('/modify')
def modify():
  status = badRequest(request)
  if status[0] not False:
    return status
  query = status[1]
  
@post('/add')
def add():
  status = badRequest(request)
  if status[0] not False:
    return status
  query = status[1]
  