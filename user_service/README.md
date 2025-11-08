#### Projet set up ####
1. git clone the project
2. create a .env file using .env.template


#### PSQL set up ####
1. Create user
*** CREATE USER motiuser WITH PASSWORD 'motipass'; ***

2. Create a db for the service
*** GRANT ALL PRIVILEGES ON DATABASE user_service_db TO motiuser; ***

3. Connect to the db
*** \c user_service_db ***

4. Grant all priviledges of the db to the created user
*** GRANT ALL PRIVILEGES ON SCHEMA public TO motiuser; ***
