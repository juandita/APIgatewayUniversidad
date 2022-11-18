from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import requests
import datetime
import re

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import JWTManager
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required


app = Flask(__name__)
cors = CORS(app)
app.config["JWT_SECRET_KEY"] = "clave-secreta-123"
jwt = JWTManager(app)

def load_file_config():
  with open("config.json") as f:
    return json.load(f)

@app.before_request
def before_request_callback():
  url = limpiar_url(request.path)
  excluded_routes = ["/login"]
  if url in excluded_routes:
    print("Ruta excluida del middleware", url)
  else:
    if verify_jwt_in_request():
      usuario = get_jwt_identity()
      rol = usuario["rol"]
      if rol is not None:
        if not validar_permiso(url, request.method.upper(), rol["_id"]):
          return jsonify({"message": "Permission denied"}), 401
      else:
        return jsonify({"message": "Permission denied"}), 401
    else:
      return jsonify({"message" : "Permission denied"}), 401

def limpiar_url(url):
  partes = url.split("/")

  for p in partes:
    if re.search("\\d", p):
      url = url.replace(p, "?")

  return url


def validar_permiso(url, metodo, id_rol):

  config_data = load_file_config()
  url_seguridad = config_data["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + id_rol
  headers = {"Content-Type": "application/json; charset=utf-8"}
  body = {
    "url" : url,
    "metodo" : metodo
  }
  response = requests.post(url_seguridad, headers=headers, json=body)
  return response.status_code == 200


@app.route("/login", methods=["POST"])
def create_token():
  data = request.get_json()
  config_data = load_file_config()
  url = config_data["url-backend-security"] + "/usuarios/validate"
  headers = {"Content-Type" : "application/json; charset=utf-8"}
  response = requests.post(url, json=data, headers=headers)

  if response.status_code == 200:
    user = response.json()
    expires = datetime.timedelta(seconds=60 * 60 * 24)
    token = create_access_token(identity=user, expires_delta=expires)
    return jsonify({"token" : token, "user_id" : user["_id"]})
  else:
    return jsonify({"msg" : "Usuario o contraseña incorrecta"}), 401

#Servicios para candidato
@app.route("/candidato", methods=["GET"])
def listar_candidadatos():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/candidato"
  response = requests.get(url)
  return jsonify(response.json())

#Servicios para mesa
@app.route("/mesa", methods=["GET"])
def listar_mesas():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/mesa"
  response = requests.get(url)
  return jsonify(response.json())

#Servicios para partidos politicos
@app.route("/partidopolitico", methods=["GET"])
def listar_partidospoliticos():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/partidopolitico"
  response = requests.get(url)
  return jsonify(response.json())

#Servicios para cuidadanos
@app.route("/cuidadano", methods=["GET"])
def listar_cuidadanos():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/cuidadano"
  response = requests.get(url)
  return jsonify(response.json())

#Servicios para votos candidato
@app.route("/votocandidato", methods=["GET"])
def listar_votos():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/votocandidato"
  response = requests.get(url)
  return jsonify(response.json())

#Servicios para votos partidos politicos
@app.route("/votopp", methods=["GET"])
def listar_votopartidopolitico():
  config_data = load_file_config()
  url = config_data["url-backend-registraduria"] + "/votopp"
  response = requests.get(url)
  return jsonify(response.json())

if __name__ == '__main__' :
  data_config = load_file_config()
  print(f"Server running: http://{data_config['url-backend']}:{data_config['port']}")
  serve(app, host=data_config["url-backend"], port=data_config["port"])