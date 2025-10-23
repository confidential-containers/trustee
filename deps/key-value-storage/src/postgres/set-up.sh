#!/bin/bash

docker run -d --name postgres -e POSTGRES_HOST_AUTH_METHOD=trust -p 6432:5432 -v $(pwd)/set-up.sql:/set-up.sql postgres:18.0

# wait for the database to start
sleep 10

# execute the content of set-up.sql file to initialize the database
docker exec -it postgres psql -U postgres -f /set-up.sql