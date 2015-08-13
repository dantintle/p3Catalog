import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	name = Column(String(250), nullable=False)
	id = Column(Integer, primary_key = True)
	email = Column(String(250), nullable=False)
	picture = Column(String(250))

class Topic(Base):
	__tablename__ = 'topic'

	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250))
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    	'id' : self.id,
	    	'name': self.name,
	    	'description' : self.description
	    }
	

class SubTopic(Base):
	__tablename__ = 'sub_topic'
	
	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250))
	topic_id = Column(Integer, ForeignKey('topic.id'))
	topic = relationship(Topic, cascade="all, delete")
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		#returns object data in easily serializable format
		return {
			'name' : self.name,
			'description' : self.description,
			'id' : self.id
		}

class SubTopicItem(Base):
	__tablename__ = 'sub_topic_item'

	name = Column(String(80), nullable = False)
	id = Column(Integer, primary_key = True)
	description = Column(String(250))
	picture = Column(String(300))
	link = Column(String(300))
	topic_id = Column(Integer, ForeignKey('topic.id'))
	topic = relationship(Topic, cascade="all, delete")
	sub_topic_id = Column(Integer, ForeignKey('sub_topic.id'))
	sub_topic = relationship(SubTopic, cascade="all, delete")
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    	'name' : self.name,
	    	'id' : self.id,
	    	'description' : self.id,
	    	'picture' : self.picture,
	    	'link' : self.link
	    }
	

class Rating(Base):
	__tablename__ = 'rating'

	id = Column(Integer, primary_key = True)
	score = Column(Integer(1))
	topic_id = Column(Integer, ForeignKey('topic.id'))
	topic = relationship(Topic)
	sub_topic_id = Column(Integer, ForeignKey('sub_topic.id'))
	sub_topic = relationship(SubTopic)
	sub_topic_item_id = Column(Integer, ForeignKey('sub_topic_item.id'))
	sub_topic_item = relationship(SubTopicItem)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
	    return {
	    'id' : self.id,
	    'score' : self.score
	    }
	



#######insert at end of file#######

engine = create_engine('sqlite:///rateeverything.db')

Base.metadata.create_all(engine)