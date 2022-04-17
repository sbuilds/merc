# README

Merc is something I made to process the PE Malware ML Learning Dataset from [Michael Lester at Practical Security Analytics](https://practicalsecurityanalytics.com/pe-malware-machine-learning-dataset/). Thanks to [Blake's R&D](https://bmcder.com/) for introducing me to the data and his work on using it [Machine Learning dataset](https://bmcder.com/blog/how-would-you-analyse-200000-executables). 

The aim this repo is a demonstration to process the binaries and extract PE data (imports, exports, sections etc.), metadata (magic, entroy, hashes etc.), and strings (static stings) as fast as possible.  

This implementation probably doesn't process them as *fast 
as it could*, however, it was made to be a scalable  implementation that could process and extract the required data (about 200k samples) in a reasonable space of time.

Following is an overview of the dataflows and containers:
![overview](design/Overview.png)

[Redis streams](https://redis.io/docs/manual/data-types/streams/) are used to provide a fast store/stream that is used to distribute the data across the workers (extract, store) for processing  

While this design has all the extraction - PE, strings etc in one container its possible to separate the extraction parts  into separate processing containers to scale different parts separately. (requires some rewriting)

The loader is just a script to prime the system, this could be improved by watching a directory or scheduling processing.

Following are the steps to setup the processing.

## docker image

The python image with the code can be built  with:

 `docker compose build`

The other containers are pulled from docker hub. 

## samples path

The docker compose specifies a bind volume for where it can read the binary files from `./samples` in the project directory. this can just be a symlink to where the samples are and the bind path will be /samples in the container.

eg: `ln -s /mnt/Mah/Binaries ./samples`

## scaling

The last run I did had 12 extract containers with 8 store containers

`docker compose up --scale extract=12 --scale store=8`

This might be overkill on the storage container but if storage doesn't keep up with the data the redis server might run out of memory. (there are further/better optimization here) 

Once the containers are running the loader.py script can be used to pre-load the database and/or the redis stream.

In order to use the loader script you need to export the database host, database user, database pass and database. For the sake of ease these can just be the defaults (from the docker compose)

`export POSTGRES_DB=merc`

`export POSTGRES_PASSWORD=pgusegr`

`export POSTGRES_USER=pguser`

`export POSTGRES_HOST=127.0.0.1`

## Bin'n'pieces

I don't remember why I called it Merc. 
