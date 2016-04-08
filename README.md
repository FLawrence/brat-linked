# brat-linked
Automatically exported from code.google.com/p/brat-linked


Useful installation notes:

> sudo apt-get install apache2
> sudo apt-get install 4store
> sudo apt-get install python
> sudo apt-get install python-pip
> sudo pip install requests
> sudo a2enmod proxy_http
> sudo apt-get install git
> cd /var/www
> sudo git clone https://github.com/FLawrence/brat-linked.git
> sudo git clone https://github.com/FLawrence/brat-linked-vis.git
> sudo mv brat-linked/ brat
> sudo chown -Rf www-data brat/work/
> sudo chown -Rf www-data brat/data/
> sudo chown -Rf www-data brat/ajax.fcgi
> rm index.html
> sudo mv brat-linked-vis/* .
> cd brat-linked-vis/
> sudo mv .git/ ../
> cd tmp/
> wget http://www.chokkan.org/software/dist/simstring-1.0.tar.gz
> tar xvzf simstring-1.0.tar.gz 
> cd simstring-1.0/
> ./configure
> nano include/simstring/memory_mapped_file_posix.h (here add #include <unistd.h> to list of includes)
> sudo make install
> cd swig/python/
> sudo apt-get install python-dev
> ./prepare.sh
> nano export_wrap.cpp (add #include <stddef.h>)
> python setup.py build_ext
> python setup.py install


> cd /var/www/brat/
> chmod -Rf 777 work/



> sudo nano /etc/init.d/4store      (NOTE: Need to edit) 


If not setup:

> python tools/norm_db_init.py data/Narrative/archetypes.txt
