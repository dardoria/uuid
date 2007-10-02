# the disttar.py file needs to be in toolpath
env = Environment(tools = ["default", "disttar"],
                  toolpath = '.')
env.DistTar("dist/uuid",
            ["uuid.asd", "uuid.html", "uuid.lisp",
             "lisplogo.png", "opensource-55x48.png",
             "emacs.jpeg"])
