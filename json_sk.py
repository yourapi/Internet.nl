import base64
import datetime
import io
import json
import uuid

from psycopg2.extras import Json

from werkzeug.datastructures import FileStorage, Headers

__all__ = ['dumps', 'loads', 'formify', 'deformify']


class CodexFileStorage:
    """The FileStorage codex is asymmetrical.
    The decoding part takes place on the server, where a FileStorage object is received. This is the server side
    representation of the file. However, when decoding, the format must be suitable for UPLOADING again.
    The encoding part assumes the requests module is used for uploading the file. A list of files which is uploaded
    consists of a tuple of: (filename, content [, content_type [, headers]])
    https://forpythons.com/how-to-upload-file-with-python-requests/#Client_Upload
    https://requests.readthedocs.io/en/master/user/quickstart/#post-a-multipart-encoded-file"""
    source = FileStorage
    attributes = 'filename name content_type content_length headers'.split()

    @classmethod
    def encode(cls, obj: source):
        """Encode the supplied object, using the FileStorage class properties and methods."""
        result = {'_type_': cls.source.__name__}
        pos = obj.stream.tell()
        obj.stream.seek(0)
        result['stream'] = base64.b85encode(obj.stream.read()).decode()
        obj.stream.seek(pos)
        for attr in cls.attributes:
            if hasattr(obj, attr):
                result[attr] = getattr(obj, attr)
        result['headers'] = json.dumps(dict(obj.headers))
        return result

    @classmethod
    def decode(cls, content: dict) -> tuple:
        """Decode the supplied structure to a BytesIO object.
        Currently, the mimetype/headers info is discarded. This can only be added when the retrieved data is promoted
        a level up, to extend the tuple """
        stream = io.BytesIO(base64.b85decode(content['stream']))
        kwargs = {}
        for attr in cls.attributes[:5]:  # Only the first 5 attributes are used in the constructor of FileStorage
            kwargs[attr] = content[attr]
        kwargs['headers'] = Headers(json.loads(content['headers']))
        stream.name = content.get('filename')
        return stream


class CodexBytesIO:
    """Store and retrieve the BytesIO object with its attributes."""
    source = io.BytesIO

    @classmethod
    def encode(cls, obj: source):
        """Encode the BytesIO object."""
        result = {'_type_': cls.source.__name__}
        pos = obj.tell()
        obj.seek(0)
        result['content'] = base64.b85encode(obj.read()).decode()
        result['name'] = obj.name
        result['pos'] = pos
        obj.seek(pos)
        return result

    @classmethod
    def decode(cls, content: dict) -> source:
        """Get the content and create a new BytesIO object"""
        result = io.BytesIO(base64.b85decode(content['content']))
        result.name = content.get('name')
        result.seek(content.get('pos', 0))
        return result


codexes = {
    CodexFileStorage.source.__name__: CodexFileStorage,
    CodexBytesIO.source.__name__: CodexBytesIO}


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime.date, datetime.datetime)):
            result = obj.isoformat()
        elif isinstance(obj, (uuid.UUID, Exception, Json)):
            result = str(obj)
        elif codexes.get(type(obj).__name__):
            return codexes[type(obj).__name__].encode(obj)
        else:
            try:
                result = json.JSONEncoder.default(self, obj)
            except Exception:
                result = str(obj)
        return result


def decode(obj):
    """If any special, typed object present at any level, decode it. If not, just return the obj as is."""
    if isinstance(obj, dict) and obj.get('_type_') and codexes.get(obj['_type_']):
        return codexes[obj['_type_']].decode(obj)
    elif isinstance(obj, dict):
        return {k: decode(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return type(obj)(decode(e) for e in obj)
    else:
        return obj


def dumps(obj, **kwargs):
    """Return a json representation of the data, with a special encoding for files. Can be used to encode complete
    payloads including multiple files into json."""
    cls = kwargs.get('cls') or JSONEncoder
    return json.dumps(obj, cls=cls, **kwargs)


def loads(string, **kwargs):
    """Accept a json-string and return the Python data for the string, including files as part of the payload."""
    if hasattr(string, 'decode'):
        string = string.decode('utf-8')
    result = json.loads(string, **kwargs)
    # Now scan all items to see if special types are present; if so, decode it:
    return decode(result)


def formify(data: dict) -> dict:
    """Take a dict and turn all key values into json representations. This way a data structure can be given as
    `data=dict` in the requests.post. The `data=` parameter of the post method takes a multi-form input.
    When only one level is supplied, the data= and json= seem identical; however, combining with uploaded files,
    the json= does not work, so the data must be supplied as a file or as a multi-form with data=, which feels more
    natural."""
    return {k: dumps(v) for k, v in data.items()}


def deformify(data: dict) -> dict:
    """Take a dict and parse the values as json, the complement of formify."""
    return {k: loads(v) for k, v in data.items()}
