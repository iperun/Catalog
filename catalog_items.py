from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, User

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Creates dummy user
User1 = User(name="Ivan Perun", email="peruni101@gmail.com",
             picture='/static/FullSizeRender1.jpg')
session.add(User1)
session.commit()

# Create first category with it's items
category1 = Category(user_id=1, name="Foot Wear")
session.add(category1)
session.commit()

item1 = Item(user_id=1, name="Sneakers",
             description="Cool looking and super comfortable!",
             price="$19.99",
             image="/static/alexander-rotker-513958-unsplash.jpg",
             category=category1)
session.add(item1)
session.commit()

item2 = Item(user_id=1, name="Boots",
             description="Great for the Winter!",
             price="$29.99",
             image="/static/pablo-e-ortiz-439934-unsplash.jpg",
             category=category1)
session.add(item2)
session.commit()

item3 = Item(user_id=1, name="Sandles",
             description="Go to foot wear for the beach!",
             price="$10.99",
             image="/static/ross-papas-324766-unsplash.jpg",
             category=category1)
session.add(item3)
session.commit()

# Second category and it's items
category2 = Category(user_id=1, name="Hats")
session.add(category2)
session.commit()

item4 = Item(user_id=1, name="Baseball Cap",
             description="Batter up!",
             price="$11.99",
             image="/static/celine-preher-379138-unsplash.jpg",
             category=category2)
session.add(item4)
session.commit()

item5 = Item(user_id=1, name="Fedora",
             description="Stylish!",
             price="$15.99",
             image="/static/craig-whitehead-256284-unsplash.jpg",
             category=category2)
session.add(item5)
session.commit()

item6 = Item(user_id=1, name="Winter Hat",
             description="Keeps you warm!",
             price="$24.99",
             image="/static/lauren-roberts-470115-unsplash.jpg",
             category=category2)
session.add(item6)
session.commit()

# Third Category and it's items
category3 = Category(user_id=1, name="Pants")
session.add(category3)
session.commit()

item7 = Item(user_id=1, name="Jeans",
             description="Go great with boots!",
             price="$24.99",
             image="/static/5theway-vietnam-519086-unsplash.jpg",
             category=category3)
session.add(item7)
session.commit()

item8 = Item(user_id=1, name="Sweatpants",
             description="Superb for exercising!",
             price="$19.99",
             image="/static/mark-adriane-540727-unsplash.jpg",
             category=category3)
session.add(item8)
session.commit()

item9 = Item(user_id=1, name="Dress Pants",
             description="When you need to be classy!",
             price="$29.99",
             image="/static/redd-angelo-581199-unsplash.jpg",
             category=category3)
session.add(item9)
session.commit()


print "Catalog Items Added Successfully"
