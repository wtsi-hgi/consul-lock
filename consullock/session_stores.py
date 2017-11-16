from abc import ABCMeta, abstractmethod
from threading import Lock, RLock
from typing import Optional, Dict

from consullock.models import Session


class DuplicateSessionError(Exception):
    """
    Raised when invalid to have multiple sessions with the same identifier.
    """


class SessionStore(metaclass=ABCMeta):
    """
    Store of sessions.
    """
    @abstractmethod
    def get_by_id(self, session_id: str) -> Optional[Session]:
        """
        Gets the session with the given identifier or `None` if such session does not exist.
        :param session_id: the session identifier
        :return: the session if found else `None`
        """

    @abstractmethod
    def add(self, session: Session):
        """
        Adds the given session.
        :param session: the session to add
        :raises DuplicateSessionError: if a session with the same identifier already exists
        """

    @abstractmethod
    def remove_by_id(self, session_id: str):
        """
        Removes the session with the given ID.

        Noop if such session does not exist.
        :param session_id: the identifier of the session to remove
        """

    @abstractmethod
    def update(self, session: Session):
        """
        Updates the record kept about the given session.

        Will add the given session if it does not exist.
        :param session: session to update
        """

    def remove(self, session: Session):
        """
        Removes the given session.

        Noop if such session does not exist
        :param session:
        :return:
        """
        self.remove_by_id(session.id)


class InMemorySessionStore(SessionStore):
    """
    In-memory session store.
    """
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = RLock()

    def remove_by_id(self, session_id: str):
        with self._lock:
            self._sessions.pop(session_id, None)

    def update(self, session: Session):
        with self._lock:
            if session.id in self._sessions:
                self.remove_by_id(session.id)
            self.add(session)

    def add(self, session: Session):
        with self._lock:
            self._sessions[session.id] = session

    def get_by_id(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id, None)
