# RESTIT.. a REST framework for DJANGO

## Quick Overview

This framework makes it easy to build a rest framework to use with any web or applicaiton development.

You can take any model and turn them into a REST Model by inheriting from RestModel.

```python
class ExampleTODO(models.Model, RestModel):
	your standard django fields
  ...
```



Next in your DJANGO app create a "rpc.py" file.

```python
# decorator that defines your routes, note the app_name is assumed
@url(r'^todo$')
@url(r'^todo/(?P<pk>\d+)$')
@login_required
def on_rest_todo(request, pk=None):
	return ExampleTODO.on_rest_request(request, pk)
```

This will give you a full rest interface into your Django model.



### But wait there's more...

This framework is pretty powerful and allow you to define how you want to return your model objects, and how deep!

```python
class ExampleTODO(models.Model, RestModel):
	class RestMeta:
		GRAPHS = {
			"default": {
        "exclude":["priority"],
				"graphs":{
					"user":"default"
				}
			},
			"list": {
        "fields":["id", "name", "priority"]
			}
		}
	user = models.ForeignKey(User, related_name="+")
  name = models.CharField(max_length=80)
  description = models.TextField(max_length=80)
  priority = models.IntegerField(default=0)
```

Above you can we we can define "graphs" that let us control what is returned.

So if we go to http://localhost:8000/rpc/rest_example/todo it will default to the "list" graph and return something that looks like...

```json
{
	"status": true,
	"size": 25,
	"count": 2,
	"data": [
		{
			"id": 1,
			"name": "test 1",
			"priority": 1,
      "user": 21
		},
		{
			"id": 2,
			"name": "test 2",
			"priority": 1,
      "user": 21
		},
	]
}
```



So if we go to http://localhost:8000/rpc/rest_example/todo?graph=default

```json
{
	"status": true,
	"size": 25,
	"count": 2,
	"data": [
		{
			"id": 1,
			"name": "test 1",
			"description": "this is test 1",
      "user": {
        "id": 21,
        "username": "jsmith",
        "display_name": "TEST USER 5",
        "avatar": "http://localhost:8000/media/ax1fg.png"
      }
		},
		{
			"id": 2,
			"name": "test 2",
			"description": "this is test 2",
      "user": {
        "id": 21,
        "username": "jsmith",
        "display_name": "TEST USER 5",
        "avatar": "http://localhost:8000/media/ax1fg.png"
      }
		},
	]
}
```

