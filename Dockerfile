# Wähle Node.js Base Image
FROM node:20

# Setze das Arbeitsverzeichnis
WORKDIR /app

# Kopiere Haupt-Package-Dateien
COPY package.json package-lock.json* ./

# Installiere Abhängigkeiten im Hauptverzeichnis
RUN npm install

# Wechsle in den Unterordner user-service und installiere dort
WORKDIR /app/auth-service

# Kopiere user-service-spezifische Dateien
COPY auth-service/package.json auth-service/package-lock.json* ./

RUN npm install

# Kopiere den restlichen Code (nachdem die deps gecached wurden)
COPY . /app

# Setze das Startkommando (optional)
CMD ["node", "auth-service/src/index.js"]
