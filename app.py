
from email import message
from functools import wraps
from  flask import Flask, jsonify ,request
from db import  Session,engine,connect_base
import json
from werkzeug.security import generate_password_hash
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy 

app=Flask(__name__)
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']=connect_base
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)
session=Session()
from models import *

@app.route('/hola',methods=[ 'GET'])
def hola():
    return jsonify({"message":"Lo estas haciendo muy bien José"})
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']
         #print("hola2")
         #print(token)

      if not token:
         return jsonify({'message': 'No has enviado el token'})

      try:
         data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=['HS256'])
         #print("hola3")
         #print(data)
         #current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
        return jsonify({'message': 'token is invalid'})
      return f(data["public_id"],*args, **kwargs)
   return decorator


@app.route('/login', methods=['GET'])  
def login_user(): 
 
  auth = request.authorization   
 # print("hola")
 # print(auth)
  if not auth or not auth.username or not auth.password:  
     #return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})    
     return jsonify({"respuesta":"No pudo verificar"})

  #user = Users.query.filter_by(name=auth.username).first()   

  with engine.connect() as con:
    user= con.execute(f"select * from usuario where username = '{auth.username}'").one()
    print(user)   
  if user[2]== auth.password:  
     token = jwt.encode({'public_id': user[1], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])  
   #  print(token)
     return jsonify({'token' : token}) 
  else:
        jsonify({"respuesta":"Contraseña incorrecta"})
  return jsonify({"Respuesta":"Contrase o usuario incorrecto"})
  #return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})    
   
    

@app.route('/create_user',methods=['POST'])
@token_required
def create_user(current_user):
    print("hola")
    print(current_user)
    if current_user == "administrador":
        data = json.loads(request.data)
        if "username" not in data:
            return jsonify({"message":"no ingreso el usarname"})
        if "password" not in data:
            return jsonify({"message":"no ingreso el password"})
        if  len(data["username"])==0:
            return jsonify({"message":"No ingreso nada en el usuario"})
        if len(data["password"])==0:
            return jsonify({"message":"no ingreso nada en la password"})


            
        #print(data)
        #print(type(data))
        #print(request)
        #print(dir(request))
        with engine.connect() as con:
            hash_password=generate_password_hash(data["password"],method="sha256")
            nuevo_usuario = Usuario(username =data["username"], password= hash_password)
            session.add(nuevo_usuario)
            try:
                session.commit()
            except:
                return jsonify({"message":"El usuario ya fue creado"})

        return jsonify({"respuesta":"Usuario creado correctamente" })
    else:
        return jsonify({"Respuesta":"El usuario no tiene permisos para crear mas usuarios"})
@app.route('/obtener_venta',methods=['GET'])
@token_required
def obtener_venta(current_user):
    data=json.loads(request.data)
    print(data)
    if 'username' not in data:
        return jsonify({"respuesta":"Userna no enviado, validar datos"})
    with engine.connect() as con:
        obtener_usuario=f"select * from usuario where username = '{data['username']}'"
        respuesta = con.execute(obtener_usuario).one()
        print(respuesta)
        obtener_venta=f"select venta from ventas where username_id ='{respuesta[0]}'"
        respuesta_ventas=con.execute(obtener_venta)
        respuesta_ventas=[i[0] for i in respuesta_ventas]     
        return jsonify({"ventas usuario":{"usuario":data['username'],"ventas":respuesta_ventas}})
@app.route('/ventas',methods=['GET'])
def obtener_ventas():
    with engine.connect() as con:
        obtener_ventas="select * from ventas"
        respuesta_ventas=con.execute(obtener_ventas)
        lista = list()
        for i in respuesta_ventas:
            lista.append({"ID_VENTA":i[0],"Valor_venta":i[2]})
    return jsonify({"Ventas":lista})

@app.route("/ventas",methods=['POST'])
def create_venta():
    data = json.loads(request.data)
    if "id_username" not in data:
        return jsonify({"Respuesta":"Id no esta en el body validar datos"})
    if "valor" not in data:
        return jsonify({"Respuesta":"La venta no esta en el body validar datos"})
    if "venta_productos" not in data:
        return jsonify({"Respuestas":"La venta no esta en el body validar datos"})
    nueva_venta=Ventas(username_id=data["id_username"],venta=data["valor"],ventas_productos=data["venta_productos"])
    db.session.add(nueva_venta)
    db.session.commit()
    return jsonify({"message":"La venta fue creada"})
@app.route('/ventas',methods=['put'])
def cambiar_venta():
    data = json.loads(request.data)
    if "id" not in data:
        return jsonify({'Respuesta':'Id no esta en el body validar datos'})
    if "valor" not in data:
        return jsonify({"Respuesta":"La venta no esta en el body validar datos"})
    venta = Ventas.query.get(data["id"])
    venta.venta = data["valor"]
    try:
        print(venta.venta)
        db.session.commit()
        
        return jsonify({"message":" venta actualizada"})
    except:
        return jsonify({"message":"No existe la vente a actualizar"})
@app.route('/ventas',methods=['delete'])
def eliminar_venta():
    data = json.loads(request.data)
    if "id" not in data:
        return jsonify({'Respuesta':'Id no esta en el body validar datos'})
    venta = Ventas.query.get(data["id"])
    try:
        db.session.delete(venta)
        db.session.commit()
        return jsonify({"message":" venta Eliminada"})
    except:
        return jsonify({"message":"La venta no existe"})
if __name__ == '__main__':

    app.run(debug=True)