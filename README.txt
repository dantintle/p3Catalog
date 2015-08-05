This is a catalog app built with Python and Flask. Users can create, read, update and delete topics, subtopics, and items in the subtopics. Users can update pictures and relevant links to each item. Login uses third party verification through Facebook and Google.

To run this project:

Install Vagrant and VirtualBox.
Clone this repository.
Launch the Vagrant VM (vagrant up).
Navigate to /vagrant/catalog.
Run your application within the VM (python /vagrant/catalog/project.py).
Access and test your application by visiting http://localhost:8000 locally.

In the project there are other files:

Static has the CSS styling for the project.
Templates have all the HTML for the web app.
The secrets files run contain the app info.
Project.py has the python code to run the project.
Database_setup.py has the database set up.