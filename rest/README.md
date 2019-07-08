# CloudFlow REST Framework

The REST framework is the backbone to the CloudFlow Platform.   Almost all of the communication between Client and Server happens here.

## RestModel

The RestModel Class is a helper class that helps existing models adapt to the REST framework.  It is not required but highly recommended.


### API helpers

#### Creating and Saving

Using createFromRequest or saveFromRequest makes it easy to create and save.

`set_` - prefix will override the naturally setting of a field so you can do any validation first.

`upload__` - is called for all files being uploaded so you can do the special handling needed.

`onSavedFromRequest` - is called after the request is saved so with the request object and any passed in kwargs.

`createFromRequest(request, **kwargs)` - this allows you to pass a request object (normally a post) and create a new model from that request.  You can also pass in any override fields after the request.

```
	MyModel.createFromRequest(request, owner=request.user)
``` 

`saveFromRequest(request, **kwargs)` - this allows you to pass a request object (normally a post) and save data to the model from that request.  You can also pass in any override fields after the request.

```
	mode_instance.saveFromRequest(request, modified_by=request.user)
``` 

#### Other Helper Methods

`getFromRequest(cls, model_name)` - @classmethod - attempts to get the model from a request, check for the classname and classname+ "_id" in the REQUEST params.


`restGetModel(app_name, model_name)` - @staticmethod - grab Model class by app and model name.

`restGetGenericModel(self, fieldname)` - grab Model class by app and model name.

`restGetGenericRelation(self, fieldname)` - grab Model class by app and model name.

## Returning JSON Graph

Graphs can easily be built automatically from your models by setting the appropriate RestMeta properties.

`getGraph(name)` - @classmethod - Specify the name of the graph you want to return.

### RestMeta

This is a Property class you add to your models to define your graphs.

By default a graph will return just the fields with no recurse into of Foreign models.

```
class MyModel(models.Model, RestModel):
   class RestMeta:
       GRAPHS: = {
           "basic": {
               "fields":[].
               "extra":[]
           }
       }

```

